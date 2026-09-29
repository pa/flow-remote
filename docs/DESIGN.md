# Design notes

flow-remote lets a phone send messages to flow sessions on a Mac and get
their replies, through a cloud mailbox that can't read or forge anything.
The byte-level format is in [PROTOCOL.md](PROTOCOL.md). This file records
the choices and the tools we compared against.

## What runs where

```
 phone (PWA)                   skoop app on GCP                     Mac
 device keys  ── HTTPS ──▶  Firebase Hosting ─▶ Cloud Run  ◀── polls ──  relay
 (non-extractable)          "mailbox": app files + API              Keychain keys
                                    │                               flow message
                                Firestore                           user/<slug>
                    envelopes, public keys, last-seen                    │
                                                                      sessions
```

- **Phone:** a web app. It seals each message to the Mac and signs it with
  its device key.
- **Mailbox:** stores sealed envelopes until they're collected. Every call
  is signed; there's no login.
- **Relay** (`flow-remote start`): checks the signature and replay list, opens the envelope,
  and runs `flow message`. Session mail
  goes back to the phone the same way.

The database exists because the phone and Mac are rarely online together
and Cloud Run drops in-memory state when it scales to zero. It holds
ciphertext, public keys, 2-minute pairing slots and last-seen times, and
no message text or private keys.

## Decisions

| Decision | Why |
| --- | --- |
| Per-device keys, not a shared account key | a lost phone is revoked on its own (`flow-remote revoke`); nothing else has to rotate |
| Every message signed and sealed | the mailbox can't read, forge or splice messages |
| Replay window of 7 days, not 5 minutes | a 5-minute window dropped every message sent while the Mac slept |
| No sign-in; requests signed by device or Mac key | a login protected nothing secret; signatures keep strangers out |
| Polling, adaptive 3s/60s | an always-open Cloud Run request costs about $45–60/month |
| Pub/Sub streaming pull later | the Mac needs a credential scoped to one subscription; skoop can't issue one yet (reported) |
| Each Mac a tenant; invites, not a shared token | your other Macs and other people's are separate by construction; an invite registers exactly one Mac |
| Mailbox is a plain container; deploy targets in `deploy/` | skoop is one host among several (see deploy/skoop, deploy/docker) |
| Every live session reachable; no allowlist | the user's choice (2026-09-29). Any paired phone can message any live session, customer sessions with skipped permissions included, so revoking a lost phone is the only limit |

## Prior art we checked

Before building multi-Mac support we compared existing tools (29 Sep 2026):

- **Claude Code Remote Control** (Anthropic): the Claude app drives local
  Claude Code sessions; per-account isolation, trusted devices, included in
  paid plans. Session-level only, and routed through Anthropic.
- **[Happier](https://github.com/happier-dev/happier)** (MIT, fork of
  Happy): native apps, self-hostable relay, end-to-end encrypted, many
  agents. Read in detail, below.
- **[Happy](https://github.com/slopus/happy)**, **[Termopus](https://github.com/heygoodluck/termopus)**,
  **[claude-code-remote](https://github.com/albertorsesc/claude-code-remote)**:
  similar session remotes (NaCl, Cloudflare + mTLS, Tailscale).

We kept flow-remote because it works on flow's inbox, not one agent's
session: `phone-dispatch`, mail across sessions, Codex as well as Claude,
and per-device revocation.

### How Happier encrypts (from its source, commit 540601b0)

Read from `docs/encryption.md`, `apps/cli/src/api/encryption.ts`,
`apps/cli/src/ui/auth.ts` and the server's key-challenge route.

- **Identity:** an account is an Ed25519 signing key plus an X25519
  content key. Login signs a random 32-byte challenge; the relay knows only
  public keys.
- **Content:** each session and machine has a random 32-byte data key.
  Data is AES-256-GCM, laid out `version | nonce(12) | ciphertext | tag`.
  The data key is sealed to the account content key with NaCl `box` and an
  ephemeral key, and stored on the relay. Any device with the account key
  reads everything.
- **Pairing a terminal:** the terminal shows a QR code with a temporary box
  key and a 32-byte secret. The phone seals the account keys to it and
  HMACs the result with the secret ("v3"). Their docs note that until v3 is
  enforced a malicious relay can downgrade to an unauthenticated legacy
  response, and that web pairing trusts whoever serves the JavaScript.
- **Relay:** Postgres holding ciphertext plus plain ids, versions and
  timestamps; clients sync over WebSockets.

### Compared with flow-remote

| | Happier | flow-remote |
| --- | --- | --- |
| Keys | one account key on every device | a key per device; only the Mac reads |
| Lost phone | rotate the account key | revoke that device |
| Authenticity | AES-GCM: any key holder can write | each message signed; replays caught |
| Pairing | QR + temporary key + HMAC secret | the same shape: QR + keys + HMAC one-time secret |
| Multiple machines / people | built in: accounts are key-identified | per-Mac tenants with single-use invites |
| Phone app | native, so pairing doesn't trust a web origin | web app, which does |
| Delivery | WebSockets | polling |

### What we're borrowing

- **Tenants identified by keys (built).** In Happier an
  account is a key pair and the relay scopes everything to it. flow-remote
  does the same per Mac:
  a phone is bound to the Mac that enrolled it, can only reach that Mac's
  queue, and a Mac can only manage its own phones. Your other Macs and
  other people's Macs are then separate by construction.
- **Pairing stays as it is.** Happier converged on the same QR + temporary
  key + HMAC secret flow, which is a useful check on ours. We already
  enforce the authenticated form; there's no legacy path to downgrade to.
- **The web-origin weakness is real.** The mailbox serves the app's
  JavaScript, so a hostile operator could ship code that uses a paired
  phone's key while it's open. Happier's answer is native apps. Ours, for
  now, is saying so plainly (README), refusing phone messages that waited
  more than 10 minutes (so a held message can't be released later), and
  later the Phase 2 Mac-side policy with Face ID approvals for anything that
  writes. Serving the app from a separate origin the user controls would
  also close most of it.

What we're not borrowing: the shared account key. It makes multi-device
sync easy, but it means a stolen phone holds the key to everything.
