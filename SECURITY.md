# Security

flow-remote passes messages from your phone to agents that can run tools
on your computer, so a security bug here can matter. Thank you for
reporting one.

## Reporting a vulnerability

Report it privately through GitHub. On this repository's **Security** tab,
choose **Report a vulnerability**. Please don't open a public issue for it.

Include what's affected, how to reproduce it, and what an attacker gains.
You'll get a reply within a week. Once a fix is released, the advisory
will credit you, unless you'd rather not be named.

## What's in scope

- Anything that lets someone other than a paired phone read, send, forge
  or replay messages, or reach the computer's own routes (`/v1/relay/*`).
- Anything that gets around pairing: the QR code's one-time secret, the
  fingerprints, or a revoked or expired device key.
- The phone app serving or running code that didn't come from the
  computer it's paired with.
- `install.sh` or `flow-remote upgrade` installing something other than
  the release it checked.

These are known limits, not vulnerabilities:

- **A paired phone can message any live session.** Revoke a lost phone
  with `flow-remote revoke`.
- **Whoever controls your tailnet's coordination server** could add a
  device to it. That device still can't pair without the QR code.
  [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) closes the gap.
- **Releases are checked against their `checksums.txt`, not signed.** That
  catches a damaged download, not a compromised GitHub account.
- **Other programs running as your user can read flow-remote's Keychain
  items and files.**

## Supported versions

Fixes go into the latest release. `flow-remote upgrade` installs it.
