# Vault recovery and key identity

The desktop app uses `%APPDATA%\MetaVault OSS` on Windows. Settings shows
the actual database path. Stop the app from its tray menu and stop any separately
started daemon before copying or restoring vault files. Closing the window may
only hide it in the tray.

## Keep the matching database and key

A password-wrapped vault needs its original `metavault.db`, its matching
`metavault.key.json`, and the password that unlocks that key. Back up the stopped
vault directory privately as a unit. A DB-only backup is not a password reset.
The daemon token authenticates local clients; it is not the encryption key.
Legacy vaults may instead depend on the original OS account's keychain key;
copying a DB to another account does not copy that key.

The wrapped key filename is resolved beside the DB, not from its basename.
Two different database filenames in the same directory therefore do not create
two independent key identities. A custom DB path is not full desktop isolation:
app state, logs, protocol registration and installer settings still use the
Windows profile. Use a disposable VM or Windows Sandbox for alpha tests.

## Missing or damaged key

If credential records exist but no wrapped, opted-in environment or legacy OS
keychain key is available, startup stops instead of offering first-run setup.
Do not delete files or create another vault in that directory. Preserve the
stopped directory and restore its matching DB/key backup. A new key cannot
decrypt records encrypted by a lost key. There is no password reset that
recovers a lost encryption key.

A password that fails to unlock may be wrong, or the wrapped key may be damaged.
Authenticated encryption cannot reliably distinguish these causes. A readable
but unrelated key file can also unlock itself without being the key for the DB.
This guard detects missing keys, not every wrong-key pairing. Do not claim that
successful key-file unlock proves credential recovery. Verify a harmless known
record after restoring a matching backup, before deleting the backup.

## Agent hash migration and rollback

The `before-agent-hash` snapshot keeps the old DB schema, including plaintext
agent bearer tokens. Keep it private. It is not a backup of the wrapped key.
The new app can read migrated token hashes; an old app cannot read that schema.
A rollback requires the old DB snapshot and its matching original encryption
key, with all processes stopped. Retain the current state separately before a
rollback. Do not mix SQLite WAL/SHM files from a different DB state. Tokens made
after the snapshot disappear on rollback; tokens rotated since it can become
valid again. Rotate affected credentials and update host configs afterwards.

Only synthetic tests cover the missing-key guard and migration snapshot behavior.
A genuine published old-installer-to-candidate Windows upgrade remains a separate
gate. Do not upgrade a valuable vault using an unverified candidate.
