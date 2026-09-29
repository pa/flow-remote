# flow-remote

Message your [flow](https://github.com/Facets-cloud/flow) sessions from your
phone, and get their replies back. `flow-remote` runs on the computer where
flow runs. It serves a small web app to your phone over your
[Tailscale](https://tailscale.com) tailnet, and hands your messages to
sessions with `flow message`. Nothing is exposed to the public internet.

```
 phone (web app)  ──Tailscale──▶  flow-remote on your computer  ──▶  flow sessions
 a key per computer               its own tailnet device,             flow message
 seals + signs every message      one HTTPS port                      user/<slug>
```

- **End to end.** Every message is sealed to its recipient (P-256 ECDH,
  AES-256-GCM) and signed by its sender (P-256 ECDSA). Tailscale's
  WireGuard encrypts the connection too, and TLS ends inside `flow-remote`.
- **Pairing by QR code.** The phone gets the computer's keys from a QR code
  shown in your terminal, and you compare fingerprints on both screens.
- **No accounts.** Phones prove who they are by signing each request with
  their own key. `flow-remote revoke` cuts one off.
- **The app on your phone.** Once installed, it opens from the phone's
  cache even when the computer is asleep. It shows your live sessions,
  where each of your messages is (sending, in the session's inbox, or
  waiting behind others), and each reply linked to the message it answers.

**A paired phone is a key to your sessions.** A message from the phone
reaches an agent that can run tools on your computer, sometimes with
permissions skipped, and any paired phone can message any live session.
If you lose a phone, revoke it straight away (see
[If you lose a phone](#if-you-lose-a-phone)).

Details: [docs/DESIGN.md](docs/DESIGN.md) covers the architecture and the
decisions behind it, [docs/PROTOCOL.md](docs/PROTOCOL.md) the byte
formats, and [docs/ROADMAP.md](docs/ROADMAP.md) other ways to reach the
computer and what's still open.

## 1. Install

You need [flow](https://github.com/Facets-cloud/flow) on the computer.
flow-remote runs on macOS today. Linux needs a key store and a systemd
service, which aren't done yet.

**From a release** (Apple Silicon shown; use `darwin_amd64` on an Intel Mac):

```bash
V=v0.1.0   # the release you want: https://github.com/pa/flow-remote/releases
# While the repo is private, download with gh (signed in with access):
gh release download "$V" -R pa/flow-remote -p "flow-remote_${V}_darwin_arm64.tar.gz" -p checksums.txt
# Once it's public, curl works too:
# curl -fLO "https://github.com/pa/flow-remote/releases/download/$V/flow-remote_${V}_darwin_arm64.tar.gz"

shasum -a 256 -c checksums.txt --ignore-missing   # check the download
tar -xzf "flow-remote_${V}_darwin_arm64.tar.gz"
install -m 755 "flow-remote_${V}_darwin_arm64/flow-remote" ~/.local/bin/   # any directory on your PATH
flow-remote version
```

The binary isn't notarized. If you downloaded it with a browser and macOS
blocks it, clear the quarantine flag:
`xattr -d com.apple.quarantine ~/.local/bin/flow-remote`. Downloads made
with `gh` or `curl` aren't quarantined.

**From source** (needs Go 1.26):

```bash
git clone https://github.com/pa/flow-remote && cd flow-remote
go install ./cmd/flow-remote        # installs to $(go env GOPATH)/bin
```

The phone app is built into the binary, so there's nothing else to deploy.

## 2. Prepare your tailnet (once)

In the Tailscale admin console, do three things:

- turn on MagicDNS and HTTPS Certificates
- add a `tag:flow-remote` with a rule that lets only your devices reach it
  on port 443
- create a single-use auth key with that tag

[deploy/tailscale](deploy/tailscale) walks through each page, the exact
settings and a policy to paste in. One thing to know first: HTTPS
certificates publish device names in public logs, so the name you give the
computer in the next step shouldn't say anything sensitive.

## 3. Set up the computer

```bash
flow-remote setup --name "Work laptop"
```

Paste the auth key when asked. Input is hidden, and the key isn't saved.
Setup joins your tailnet as a device called `flow-remote-work-laptop`,
fetches its HTTPS certificate, and prints the address phones will use,
like `https://flow-remote-work-laptop.<tailnet>.ts.net`. The name is part
of that address, so pick it once.

The computer's keys and its list of paired phones go in the login Keychain
(service `flow-remote`). Everything else is in `~/.flow-remote/`. Programs
you run can read those Keychain items, so they're protected about as well
as your files are, not isolated from your own user.

## 4. Run it in the background

```bash
flow-remote start     # a launchd agent: runs now, at every login, and restarts on a crash
flow-remote status    # running? the address phones use, and the last log lines
flow-remote stop      # stop it and remove it from login
```

`flow-remote run` runs it in the foreground instead, which is handy for
watching the log. Only one runs at a time for a given home folder.

The computer has to be awake for messages to go through. To keep a Mac
awake while it's plugged in, go to System Settings > Battery > Options and
turn on "Prevent automatic sleeping on power adapter when the display is
off".

## 5. Pair your phone

1. Install the Tailscale app on the phone, sign in to the same tailnet, and
   turn it on.
2. On the computer, run `flow-remote pair`. It shows a QR code for 2
   minutes (`--png FILE` saves it as an image as well).
3. **First time on an iPhone:**
   1. Scan the code with the camera. It opens Safari, which shows how to
      add flow-remote to your Home Screen.
   2. Add it, and open the app from the Home Screen. An installed app keeps
      its storage apart from Safari, and that's where its keys have to live.
   3. Scan again from inside the app.

   On Android you can pair in the browser and install after.
4. In the app, tap **Scan the QR code** (or **Take a photo of the QR code**
   if the live camera won't start), then **Pair**.
5. Check that the fingerprints on the two screens match, and type `y` on
   the computer.

## Using the app

- **Sessions.** The main screen lists your live flow sessions, with
  **New replies** first. A session holding a message of yours that hasn't
  been answered sits under **Waiting for a reply**, with a line saying
  where the message is.
- **Threads.** Each message you send shows its state: sending, waiting for
  the computer, or "waiting in the session's inbox" with its place in the
  queue ("2 of 3") until the session answers it. flow can't yet say when a
  session reads its inbox, so a reply is the only evidence it did.
- **Replies.** A session's reply opens with a quote of the message it
  answers, and tapping the quote jumps to it. To answer a particular
  message, tap it or swipe it to the right. Your message then goes with
  `--reply-to`, and the message you answered is marked read in flow.
- **When the computer can't be reached,** the app says why, as far as it
  can tell. Either the phone is offline, Tailscale is off on the phone, or
  the computer isn't answering (asleep, or `flow-remote` isn't running).
  Messages you write wait on the phone and go when the computer is back,
  for up to 10 minutes. After that the app asks you to send again.
- **Updates.** A new build of `flow-remote` serves a new app. The phone
  picks it up when the app comes to the front, when the computer is
  reachable again, or within 5 minutes, and reloads by itself.

## More computers

Each computer runs its own `flow-remote` with its own tailnet name. To
reach several from one app, point the others at the first one's app when
you set them up:

```bash
flow-remote setup --name "Home desktop" --app https://flow-remote-work-laptop.<tailnet>.ts.net
```

`flow-remote pair` on that computer then gives a QR code that opens your
existing app. The app keeps a separate key per computer and shows a
switcher. In the app, **Settings > Pair another computer** opens the
scanner.

## If you lose a phone

On each computer it's paired with, list its phones and revoke the lost one:

```bash
flow-remote devices     # phones, with when each last checked in
flow-remote revoke <device-id>
```

The computer refuses that key from then on. A phone that's gone unused for
30 days stops working anyway. A revoked or expired phone comes back with
**Pair again**, which gives it a new key.

## Commands

| Command | What it does |
| --- | --- |
| `setup [--name N] [--app URL]` | join your tailnet and serve phones from this computer (the default, `--tunnel tailscale`) |
| `setup --mailbox URL [--name N]` | use a hosted mailbox instead (see below) |
| `start` / `stop` / `status` | run in the background as a launchd agent, stop it, check it |
| `run` | run in the foreground |
| `pair [--png FILE]` | show a QR code and enroll a phone |
| `devices [--all]` / `revoke <device-id>` | list this computer's phones with when each last checked in (`--all` adds revoked ones), or cut one off |
| `invite`, `tenants`, `remove-tenant <mac-id>` | hosted mailbox only: an admin's invites and tenants |
| `version` | print the version |

## What's in ~/.flow-remote

| Path | What |
| --- | --- |
| `config.json` | the settings `setup` wrote |
| `tailscale/` | the tailnet device's identity (mode 0700); delete it to leave the tailnet |
| `mailbox.db` | messages waiting for a phone, pairing slots and last-seen times (sealed envelopes only) |
| `mailbox.sock` | how `pair`, `devices` and `revoke` reach the running server (mode 0600) |
| `seen.json`, `forwarded.json` | the replay guard, and which session mail went to the phone |
| `audit.log`, `relay.log` | what was delivered, refused or forwarded (never message text), and the service's log |

## Without Tailscale: a hosted mailbox

If a phone can't run Tailscale (iOS allows one VPN at a time), a hosted
mailbox can carry sealed envelopes between the phone and the computer
instead, and `flow-remote` polls it. The mailbox serves the phone app's
code, so whoever runs it could change that code. Run your own.

- [deploy/skoop](deploy/skoop): Cloud Run and Firestore on GCP, with a
  custom domain.
- [deploy/docker](deploy/docker): Docker Compose with MongoDB and Caddy on
  any machine.

The first computer registers with the mailbox's setup token and becomes
its admin. Others join with `flow-remote invite`:

```bash
FLOW_REMOTE_SETUP_TOKEN=<token> flow-remote setup --mailbox https://flow.example.com --name "Work laptop"
FLOW_REMOTE_INVITE=<code> flow-remote setup --mailbox https://flow.example.com --name "Home desktop"   # on another computer
```

Clear `MAILBOX_SETUP_TOKEN` once the first computer is set up.

| Mailbox variable | Meaning |
| --- | --- |
| `PORT` | where to listen (default 8080) |
| `MAILBOX_STORE` | `mongo` in production; `memory` for local runs (refused on Cloud Run) |
| `MAILBOX_MONGO_URI` | a MongoDB connection string (Firestore's MongoDB mode works) |
| `MAILBOX_MONGO_DB` | the database name; defaults to the one in the URI's path |
| `MAILBOX_SETUP_TOKEN` | registers the first, admin computer; clear it afterwards |
| `MAILBOX_DEVICE_IDLE_DAYS` | phone keys unused this long stop working (default 30; `0` never) |
| `MAILBOX_TRUSTED_PROXIES` | CIDRs of front ends whose `X-Forwarded-For` entry names the client (default `66.249.64.0/19`, Firebase Hosting's edge) |
| `MAILBOX_DEBUG_ERRORS` | `1` returns store errors to callers, for diagnosis |
| `MAILBOX_WEB_DIR` | serves the phone app; the Docker image sets `/web` |

Health check: `GET /v1/health` returns `ok` once the store is connected.

## Releases

CI (`.github/workflows/ci.yml`) runs on every push:
- the Go tests, against a real MongoDB
- the phone app's tests
- a macOS build of `flow-remote`
- the mailbox's Docker image

To publish binaries, push a version tag:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` then builds `flow-remote` for macOS
(arm64, amd64) and the mailbox for Linux (amd64, arm64), stamps the
version, and attaches them with `checksums.txt` to a GitHub release.

## Development

```bash
go test ./...                       # includes end-to-end serve tests and WebCrypto interop under Node
node --test web/js/*.test.mjs       # the phone app's own tests
FLOW_REMOTE_MONGO_URI=mongodb://127.0.0.1:27017 go test ./internal/mailbox/   # the Mongo store
```

To try the app on this computer without Tailscale, use a scratch home that
doesn't touch your Keychain or your real setup:

```bash
export FLOW_REMOTE_HOME=/tmp/fr FLOW_REMOTE_KEYSTORE=dir
go build -o bin/flow-remote ./cmd/flow-remote
./bin/flow-remote setup --tunnel none --listen 127.0.0.1:8484 --public-url http://127.0.0.1:8484
./bin/flow-remote run               # then, in another shell with the same exports: ./bin/flow-remote pair
```

Browsers treat `localhost` and `127.0.0.1` as secure, so the app works
there over plain http. Every other address needs https.

When you change anything under `web/`, bump `BUILD` in `web/js/app.js` and
`CACHE` in `web/sw.js` together. The app loads from its cache first, so
without a new build number phones keep the old files.

## License

MIT, see [LICENSE](LICENSE). The vendored libraries in `web/vendor` keep
their own licenses (jsQR: Apache-2.0, qrcode-generator: MIT); see
[web/vendor/VENDOR.md](web/vendor/VENDOR.md).
