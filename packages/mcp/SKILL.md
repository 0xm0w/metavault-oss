---
name: add-secret-to-vault
description: Ask the human to add a credential to MetaVault OSS via a deeplink when you need a secret you do not have. Only the human ever types the secret.
---

# Add a secret to the vault

Use this when you need a credential (API key, token, password) that is not
already in MetaVault OSS — for example `list_aliases` does not contain the alias
you need, or `request_capability` was denied with `unknown-alias`.

## Workflow

1. **Request an enrollment.** Call `request_enrollment` with the `alias` and
   `scope` you need (and a short `reason` explaining why). It returns an
   `enrollmentId` and a `deeplink` like
   `openvault://add?alias=stripe&scope=charges.read&enrollment=<id>`.
   Creating an enrollment grants nothing — it only pre-fills a form.

2. **Present the deeplink to the user.** Show the exact deeplink to the
   human and ask them to open it. The link opens the MetaVault OSS app's
   *Add credential* dialog with alias, scope, and website already filled.
   Tell the user: only they type the secret, and the secret never passes
   through you or this conversation. Do not ask the user to paste the
   secret to you, and never handle, repeat, or store the secret yourself.

3. **Poll for completion.** Call `enrollment_status` with the
   `enrollmentId` every few seconds. Statuses: `pending` (waiting for the
   human), `completed` (credential saved), `expired` (10-minute TTL ran
   out — request a fresh enrollment if still needed). Stop polling on
   `completed` or `expired`.

4. **Test the credential.** On `completed`, call `request_capability` for
   the alias/scope you need with a clear reason and observe the result:
   `executed` (it worked), `awaiting-approval` (tell the user a grant is
   waiting for their approval in MetaVault OSS), or `denied` (report the
   reason). The test result — not the save alone — is the proof.

5. **Report the outcome to the user.** Say which alias/scope was added
   and what the test showed (executed / awaiting approval / denied with
   reason). Never include any secret value in the report — you never had
   it, and that is by design.

## Rules

- Never ask for, receive, log, or repeat secret values.
- Enrollments expire after 10 minutes; create a new one instead of
  reusing an expired `enrollmentId`.
- If the user declines or the enrollment expires, say so plainly and stop.
