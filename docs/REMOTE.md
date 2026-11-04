# Remote Connections (candidate)

Status: **unreleased candidate**. Remote access is off by default. The
gateway itself accepts loopback connections only; reachability from other
networks comes from the optional app-managed SSH transport below, which keeps
every listener on loopback at both ends.

## What it is

Remote Connections let a second device you own run agents that request
capabilities from this vault over mutually authenticated TLS 1.3. The phone or
laptop never sees secrets: requests travel to the same vaultd, the same policy
ceilings apply, the marshal assesses the same metadata, and approval happens on
the desktop as usual.

## Architecture

- A **gateway** process binds two loopback-only listeners (configurable
  ports):
  - **Pairing** on `127.0.0.1:7078`: server-only TLS 1.3. Exactly two POST
    routes (`/pair/begin`, `/pair/status`), strictly rate-limited. The
    pairing client cannot validate the vault's identity on this leg - no
    trust anchor exists yet - so the certificate presented here is NOT yet
    authenticated; authenticity comes only from the human SAS comparison
    below. Outside an explicit pairing window (a live, unconfirmed,
    unexpired vault-side session) the listener is inert: `/pair/begin` is
    refused before any body is read or code is compared.
  - **Devices** on `127.0.0.1:7080`: strict mutual TLS 1.3. A client
    certificate chaining to the vault CA is required at the TLS handshake
    itself, so certificate-less and foreign-CA connections are refused
    before any HTTP exists. This listener forwards allowlisted requests to
    vaultd over the loopback daemon socket.

  Port allocation is collision-free on one host: 7077 vaultd, 7078 gateway
  pairing, 7080 gateway devices, and 7079 belongs to the device-side shim's
  own IDE-facing channel - so a device client and this vault can run on the
  same machine.
- Either listener failing to bind stops the whole gateway; it never runs
  half-configured.
- vaultd and the gateway share a **gateway secret** (loopback-only file, 0600).
  Every forwarded request carries an HMAC stamp (device id, transport, method,
  path, body hash, timestamp, nonce) over that secret. Stamps expire after a
  short window and nonces are single-use.
- vaultd fails closed on any request that carries device-identity headers
  without a fully valid stamp, so a local process cannot spoof a remote
  device and a remote caller can never pose as local.
- On a device-stamped request vaultd ignores any presented daemon token: a
  remote device can never exercise human-decision routes even if the token
  leaked to it.
- Origin (`local`/`remote`), device id and transport are provenance stamped by
  the daemon from the authenticated session, never taken from the request
  body. Audit rows carry all three.

## Pairing

1. Desktop: Settings > Connections > Start pairing. vaultd mints a one-time
   pairing code (5 minute expiry, in-memory only).
2. Device: `metavault pair` with the code. The device joins over the gateway
   with its freshly generated client key.
3. Both screens show a verification code (SAS) derived from the handshake
   transcript (TLS 1.3 exported keying material) plus both public identities,
   the pairing code, both nonces and the announced device port - so a relay
   rewriting the device-port announcement breaks the comparison instead of
   redirecting the pinned transport. Confirm on the desktop only if both
   match exactly. "Codes do not match" cancels and issues nothing.
4. Only after confirmation does vaultd sign the device certificate (vault CA,
   1 year) and store the device record. The pairing confirmation is bound to
   the currently displayed session: a stale UI confirmation or a replaced
   session is rejected.

Pairing state never persists across daemon restarts. Pairing codes, SAS values
and session identifiers are never logged.

## Devices and policy

Each paired device has a record (name, platform, certificate fingerprint) and
per-alias write policy. Read scopes are always within the vault's existing
ceilings; write scopes additionally require the device's per-alias allowance.
**Revoking** a device deletes its record, its per-alias policies and its bound
agent tokens. Its subsequent requests are rejected, even on connections it
already holds open; requests already executing are not cancelled retroactively.

## Remote approvals require your app PIN

Approving a remote-origin request requires fresh local presence: a single-use,
60-second proof minted by a real app-PIN verification. This is enforced at two
boundaries:

- **Main process:** the desktop app's IPC boundary rejects forged renderer
  approval calls, and rejects when the grant cannot be found or daemon state
  is unreadable (no silent local fast path).
- **Daemon:** direct token-authenticated `/approve` and `/approve-always`
  calls on remote-origin grants also require a daemon-minted proof, so the
  app is not the only enforcement point. Proofs are single-use; replays and
  expired proofs are rejected. Turning the requirement off
  (`requireAuthForRemoteApproval: false`) itself requires a fresh proof at
  both boundaries.

**Windows Hello cannot authorize remote approvals.** The daemon's biometric
result is caller-attested (the daemon cannot verify a Hello prompt happened),
so it never mints presence proofs. If you have no app PIN set, remote
approvals fail closed and the app says so.

### Exact authority statement

Presence proofs are mintable only by knowledge of the real app PIN. A holder
of the daemon token who does not know the PIN cannot mint a proof, cannot
disable the presence requirement, and cannot replace the PIN (replacing an
existing PIN requires the current one). One residual: when no PIN is
configured, any local caller (including a token holder) can set a first PIN
and thereafter mint proofs, but with no PIN configured remote approval already
fails closed for everyone. A local process holding the daemon token is full
local admin by design: it can read vault contents directly. Presence
enforcement therefore protects the **remote client path** and the **app /
renderer path**; it is not local-admin resistance, and it is not claimed to be.

### Opting out weakens protection

If you deliberately turn off "Require app PIN for remote approvals", paired
devices can get approvals without any local check. The app states this plainly
when you turn it off, and the change itself requires your PIN.

## SSH transport (app-managed reverse tunnel)

Optional, off until set up. Settings > Connections > Remote connection lets
the desktop dial OUT to an SSH server you control and reverse-forward the two
gateway listeners onto that server's loopback:

- `ssh -N -T` with `127.0.0.1:<relay pairing port>` -> `127.0.0.1:7078` and
  `127.0.0.1:<relay device port>` -> `127.0.0.1:7080`. The relay never needs
  `GatewayPorts`: nothing is exposed beyond the server's own loopback.
- No SSH server runs on this PC; only the OpenSSH client is used (the Windows
  inbox OpenSSH is preferred over PATH).
- Key-only auth: the app generates an ed25519 keypair under the app data
  folder (`ssh-tunnel/`, 0700; key and config 0600 - on Windows, owner-only
  ACLs via icacls with the effective ACL's trustee SIDs verified, failing
  closed). The setup wizard shows an `authorized_keys` line with `restrict`,
  `port-forwarding`, a `command="false"` forced command, two `permitlisten`
  entries and a `permitopen` blackhole. Verified against a real sshd:
  `restrict` alone neither re-enables `-R` (so `port-forwarding` is required)
  nor blocks shell/exec or the sftp subsystem (so the forced command is what
  blocks those); pty/agent/X11 stay denied by `restrict`.
- Required server policy: per-key options cannot genuinely deny LOCAL
  forwarding (`permitopen` has no deny-all; a blackhole target still gets a
  connect attempt). The wizard therefore also shows a `Match User` block
  (`AllowTcpForwarding remote`, agent/X11/TTY off) for the server's
  sshd_config. Before finishing, setup runs live negative probes through the
  installed key - shell/exec canary, sftp `SSH_FXP_INIT`, pty allocation,
  and a `-L` open that must come back "administratively prohibited". If any
  probe shows more than the two forwards, setup refuses to finish and saves
  nothing (the failure names what to fix).
- Host key pinning without blind TOFU: setup scans the server's host key,
  and the SHA256 fingerprint you paste (verified against your server
  provider) must match exactly before anything is saved. The pinned key goes
  into the app's own `known_hosts` and every connection uses
  `StrictHostKeyChecking=yes`. A host key that later fails to match is a
  terminal error and flips the tunnel off - it never silently reconnects.
- `BatchMode`, `IdentitiesOnly`, agent/X11/local command off, no control
  sockets, and every option pinned on the command line with an empty `-F`
  config file, so user or system ssh config cannot add behaviour. (No
  `ClearAllForwardings`: it clears command-line `-R` too.) No secret ever
  appears on the command line or in the log.
- "Connected" is only reported after the server has confirmed BOTH reverse
  forwards (with `ExitOnForwardFailure=yes` a refused forward fails the
  attempt) and the local gateway listeners answer. It says nothing about
  vault unlock, pairing, policy or approval.
- Automatic reconnect is bounded (five attempts, 2-32s backoff) and resets
  after a stable minute. Disconnect and app quit stop exactly the ssh child
  the app spawned; nothing is killed by PID lookup.
- Remove connection deletes the pinned host key, config and keypair locally;
  the UI tells you to remove the key line and the Match block on the server.

The tunnel is transport only. Pairing (SAS), mTLS device certificates,
policy ceilings and PIN-gated remote approvals are unchanged.

## Current limits

- The gateway binds loopback only. Cross-network reachability is possible
  through the optional SSH transport above; no tailnet, LAN or public
  listener is enabled, and the relay sees loopback-bound forwards only.
- Packaged Windows launch of the gateway from the installed app is verified in
  CI; packaged target-device PRF custody remains unproved.
- Legacy 0.1.0 compatibility, automatic legacy adoption and encrypted export
  are not part of this candidate.
- Onboarding for other IDEs, model chat or platforms is unproved.
- The installer artifact for this candidate is produced by CI on the merged
  branch; local dev builds are not the delivery vehicle.
