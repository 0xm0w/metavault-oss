# Remote Connections (candidate)

Status: **unreleased candidate**, loopback-isolated. Remote access is off by
default and this build accepts loopback connections only; no network transport
(Tailscale, LAN or otherwise) is enabled yet. Enabling it on another network
interface is a separate, explicit future decision.

## What it is

Remote Connections let a second device you own run agents that request
capabilities from this vault over mutually authenticated TLS 1.3. The phone or
laptop never sees secrets: requests travel to the same vaultd, the same policy
ceilings apply, the marshal assesses the same metadata, and approval happens on
the desktop as usual.

## Architecture

- A **gateway** process binds `127.0.0.1:7078` (configurable port, loopback
  only). It terminates mTLS from paired devices and forwards requests to
  vaultd over the loopback daemon socket.
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
   transcript (TLS 1.3 exported keying material). Confirm on the desktop only
   if both match exactly. "Codes do not match" cancels and issues nothing.
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

## Current limits

- Loopback only. No tailnet, LAN or public listener is enabled in this build.
- Packaged Windows launch of the gateway from the installed app is verified in
  CI; packaged target-device PRF custody remains unproved.
- Legacy 0.1.0 compatibility, automatic legacy adoption and encrypted export
  are not part of this candidate.
- Onboarding for other IDEs, model chat or platforms is unproved.
- The installer artifact for this candidate is produced by CI on the merged
  branch; local dev builds are not the delivery vehicle.
