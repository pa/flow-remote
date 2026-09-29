# Design notes

flow-remote lets a phone send messages to flow sessions on a computer and
get their replies. The byte-level format is in [PROTOCOL.md](PROTOCOL.md).
This file records how it's put together, the choices behind it, and the
tools we compared against.

## What runs where

By default, `flow-remote` serves the phone itself, over the tailnet.

```
 phone (PWA)                                 your computer
 device keys           ── Tailscale ──▶  flow-remote run (one process)
 (non-extractable)       WireGuard,        ├─ tsnet device, :443 TLS ── app files + phone API
 app from its cache      TLS ends here     ├─ mailbox server + bbolt (mailbox.db)
                                           │     └─ unix socket (0600) ◀── relay, pair, devices, revoke
                                           └─ relay ── flow message / flow inbox ── sessions
```

- **Phone:** a web app, installed to the home screen. It seals each message
  to the computer, signs it with its device key, and signs every request.
  It opens from its cache when the computer can't be reached.
- **tsnet:** Tailscale's Go library, inside the process. The process is its
  own tailnet device with a software network stack. The computer gets no
  VPN interface, and nothing else on it becomes reachable. TLS ends here,
  so only this computer can serve or change the app's code.
- **Mailbox server:** holds sealed envelopes until they're collected, with
  this computer as its only tenant and a bbolt file for storage. Phones reach
  only the phone routes. The computer's own routes are on a unix socket.
- **Relay:** checks each envelope's signature and the replay list, opens
  it, and runs `flow message`. It reads the human's inbox with
  `flow inbox --as user --all` and forwards sessions' mail to the phone.
  A post from a phone wakes it at once.

Until 2026-09-30 there was also a hosted mailbox (Cloud Run and
Firestore via skoop, or Docker and MongoDB) for phones without Tailscale.
It was removed once Tailscale worked; it's in the git history, and
[ROADMAP.md](ROADMAP.md) lists what could take its place.

## Decisions

| Decision | Why |
| --- | --- |
| Per-device keys, not a shared account key | a lost phone is revoked on its own (`flow-remote revoke`); nothing else has to rotate |
| Every message signed and sealed | whatever carries it (Tailscale's relays, a mailbox) can't read, forge or splice messages |
| Replay window of 7 days, not 5 minutes | a 5-minute window dropped every message sent while the computer slept |
| No sign-in; requests signed by device or computer key | a login protected nothing secret; signatures keep strangers out |
| Serve from the computer over Tailscale, by default (2026-09-29) | no server to run or pay for, nothing public, and TLS ends on the computer, so nobody in between can change the app's code |
| tsnet inside the process, not the Tailscale app | only this process joins the tailnet; the computer's other services stay unreachable, and the computer doesn't need the Tailscale app |
| A tagged, single-use auth key, never a flag, never saved | tagged devices don't expire after 180 days, and the key is useless after the join |
| The mailbox server reused in-process, over a unix socket | the relay and the CLI keep the one signed API; internal/relay doesn't know which mode it's in |
| bbolt for the computer's store | one file, crash-safe; it holds one person's queues, so scanning is fine |
| Every live session reachable; no allowlist (2026-09-29) | the user's choice. Any paired phone can message any live session, customer sessions with skipped permissions included, so revoking a lost phone is the only limit |
| Forward mail even if already read | another session's `flow inbox pop` can read the human's queue first; the relay keeps its own record of what it forwarded |
| The app loads from its cache first | a request to a sleeping computer over Tailscale hangs rather than fails, and the app must open anyway |
| "Waiting" means no answer yet | flow can't say when a session reads its inbox (Facets-cloud/flow#100); the evidence is a reply naming the message, or failing that any later reply |
| Say why a computer is unreachable, judged from how the request failed | a tailnet name isn't in public DNS, so with Tailscale off the request fails at once; a computer that's down gives no answer until the 10 s timeout |
| On an iPhone, pair in the installed app, not in Safari | a home-screen app keeps its storage apart from Safari, and keys made in Safari would stay there |
| Polling every 3 s while the app is open | simple, and cheap on a tailnet |
| Hosted mailbox removed (2026-09-30) | Tailscale covered the need; the skoop deployment was deleted and the code went with it |
| `install.sh` and `flow-remote upgrade` | one command to install; the download is checked against the release's checksums.txt |

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
| Keys | one account key on every device | a key per device; only the computer reads |
| Lost phone | rotate the account key | revoke that device |
| Authenticity | AES-GCM: any key holder can write | each message signed; replays caught |
| Pairing | QR + temporary key + HMAC secret | the same shape: QR + keys + HMAC one-time secret |
| Multiple machines / people | built in: accounts are key-identified | one app pairs with each computer separately, a key per computer |
| Phone app | native, so pairing doesn't trust a web origin | web app, which does |
| Delivery | WebSockets | polling, woken at once on the computer |

### What we're borrowing

- **Tenants identified by keys (built).** In Happier an
  account is a key pair and the relay scopes everything to it. flow-remote
  does the same per computer:
  a phone is bound to the computer that enrolled it, can only reach that
  computer's queue, and a computer can only manage its own phones. Your other computers and
  other people's are then separate by construction.
- **Pairing stays as it is.** Happier converged on the same QR + temporary
  key + HMAC secret flow, which is a useful check on ours. We already
  enforce the authenticated form; there's no legacy path to downgrade to.
- **The web-origin weakness is real, and Tailscale mostly closes it.**
  Whoever serves the app's JavaScript could ship code that uses a paired
  phone's key while it's open. Happier's answer is native apps. Serving
  from the computer over Tailscale means TLS ends on your computer, so
  nobody else can serve that code. Phone messages that waited more than 10 minutes
  are refused, so a held message can't be released later. A Face ID lock
  on sending is still to come.

What we're not borrowing: the shared account key. It makes multi-device
sync easy, but it means a stolen phone holds the key to everything.
