# Security policy

Tijori is **pre-alpha**. It has not been audited and must not be trusted with
real data yet. We still want to hear about every security problem, now more
than ever, because the on-disk format is not frozen.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.**

Report it privately through GitHub's private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- what an attacker can do, and what they need (the drive only? an unlocked
  session? local code execution?);
- the affected component (`spec/`, `core/`, `cli/`, `mount/`, `desktop/`,
  `android/`) and version or commit;
- steps or a sample vault that reproduce it, if you have them.

## What to expect

- We acknowledge reports within 7 days.
- We keep you informed while we investigate and fix the issue.
- We agree a disclosure date with you, normally within 90 days of the report,
  and credit you in the advisory unless you prefer otherwise.

## Scope

In scope: the vault format and its cryptography, anything that leaks plaintext,
file names, keys or passwords, parser bugs reachable from a hostile drive, and
anything that weakens the host hardening of mounted vaults.

Known limits are documented in [`spec/SPEC.md`](spec/SPEC.md) §14 (for example,
a compromised host sees everything while a vault is unlocked). Reports that
only restate those limits are welcome as discussion but are not vulnerabilities.
