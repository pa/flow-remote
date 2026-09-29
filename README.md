# flow-remote

Message your [flow](https://github.com/Facets-cloud/flow) sessions from your
phone, and get their replies back, through a mailbox that can't read or
forge messages in transit.

```
 phone (web app)            mailbox (any host)              your computer
 a key per computer ──HTTPS──▶ stores sealed envelopes ◀── flow-remote relay
 seals + signs              checks signatures,              opens, checks,
 every message              knows only public keys          runs `flow message`
```

- **End to end.** Every message is sealed to its recipient (P-256 ECDH,
  AES-256-GCM) and signed by its sender (P-256 ECDSA). The mailbox sees who
  talks to whom and when, and nothing else.
- **No accounts.** computers and phones prove who they are by signing each
  request. The mailbox holds only public keys.
- **Tenants.** Each computer is its own tenant. A phone belongs to the computer that
  paired it and can only reach that computer. Your other computers, and other
  people's, are separate.
- **Per-device revocation.** `flow-remote revoke` cuts off one phone. Its
  key signs nothing afterwards.

**What you still trust the mailbox for.** The mailbox also serves the phone
app's code. Whoever runs it (you, if you deploy your own) could ship a
modified app that uses a paired phone's key while it's open, and so send
messages as that phone. It still can't read messages already sent, or
impersonate your computer. Run your own mailbox, or only join one run by
someone you trust. On a shared mailbox, invited computers are isolated from
each other but not from its operator.

Details: [docs/DESIGN.md](docs/DESIGN.md) covers the architecture,
decisions and prior art, and [docs/PROTOCOL.md](docs/PROTOCOL.md) the byte
formats.

## Or: serve from your computer over Tailscale

You don't need a mailbox at all if your phone runs Tailscale. `flow-remote`
can join your tailnet as its own device and serve the app and API from the
computer, with nothing on the public internet. See
[deploy/tailscale](deploy/tailscale). The rest of this page covers a hosted
mailbox.

## 1. Run a mailbox

The mailbox is one container: the API plus the phone app. Pick a host:

- **[deploy/skoop](deploy/skoop)**: Cloud Run, Firestore and Firebase
  Hosting on GCP, including a custom domain.
- **[deploy/docker](deploy/docker)**: Docker Compose with MongoDB and Caddy
  on any machine.
- **Anything else** that runs a container over HTTPS: see
  [Mailbox configuration](#mailbox-configuration).

Keep the `MAILBOX_SETUP_TOKEN` you set. Your first computer needs it.

## 2. Set up your computer

You need [flow](https://github.com/Facets-cloud/flow) on the computer. Install
`flow-remote` from a release, or build it.

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

Then set up the computer. The first computer on a mailbox uses its setup token and
becomes the admin:

```bash
FLOW_REMOTE_SETUP_TOKEN=<token> flow-remote setup --mailbox https://flow.example.com --name "Work laptop"
```

Keys go in the login Keychain (service `flow-remote`). Settings and logs
go in `~/.flow-remote/`. The Keychain items are readable by other programs
you run, so this protects the keys about as well as file permissions do.
It doesn't isolate them from your own user.

## 3. Start the relay

```bash
flow-remote start     # a launchd agent: runs now, at every login, and restarts on a crash
flow-remote status    # is it running? the last few log lines
flow-remote stop      # stop it and remove it from login
```

`flow-remote run` runs it in the foreground instead, which is handy for
debugging. Only one relay runs at a time.

## 4. Pair your phone

1. Open the mailbox URL on your phone. On an iPhone, tap Share, then
   **Add to Home Screen**, and open it from there, because that's where its
   keys will live.
2. On the computer, run `flow-remote pair`. It shows a QR code for 2 minutes
   (`--png FILE` saves it as an image as well).
3. In the app, tap **Scan the QR code**, or **Take a photo of the QR code**
   if the live camera won't start. Then tap **Pair**.
4. Check that the fingerprints on the two screens match, and type `y` on
   the computer.

The phone now lists your live sessions. Sessions in
`~/.flow-remote/allow.txt` accept messages; the rest are read-only:

```
phone-dispatch     # a task slug
#personal          # every live task with this tag
*                  # every live session
```

The relay reads this file when it starts, so run `flow-remote start` again
after changing it.

## 5. More computers, yours or anyone's

On an admin computer:

```bash
flow-remote invite        # a single-use code, valid for 24 hours
```

On the new computer, after installing:

```bash
FLOW_REMOTE_INVITE=<code> flow-remote setup --mailbox https://flow.example.com --name "Home desktop"
flow-remote start && flow-remote pair
```

Pair from the same phone with **Settings → Pair another computer**. The app
keeps a separate key per computer and shows a switcher.

Admin commands: `flow-remote tenants` lists computers, and
`flow-remote remove-tenant <mac-id>` removes one, together with its phones
and its mail.

Once your first computer is set up, clear `MAILBOX_SETUP_TOKEN` on the mailbox.
Invites cover everything after that.

## If you lose a phone

On the computer it's paired with, list its phones and revoke the lost one:

```bash
flow-remote devices
flow-remote revoke <device-id>
```

The mailbox and the relay both refuse that key from then on. A phone
that's gone unused for `MAILBOX_DEVICE_IDLE_DAYS` (default 30) stops
working anyway. A phone that's revoked or expired comes back with **Pair
again**, which gives it a new key.

## Commands

| Command | What it does |
| --- | --- |
| `setup --mailbox URL [--name N]` | save the mailbox and register this computer (`FLOW_REMOTE_SETUP_TOKEN` or `FLOW_REMOTE_INVITE`) |
| `start` / `stop` / `status` | run the relay as a launchd agent, stop it, check it |
| `run` | run the relay in the foreground |
| `pair [--png FILE]` | show a QR code and enroll a phone |
| `devices [--all]` / `revoke <device-id>` | list this computer's active phones with when each last checked in (`--all` adds revoked ones), or cut one off |
| `invite` | (admin) a single-use code for another computer |
| `tenants` / `remove-tenant <mac-id>` | (admin) list or remove computers |
| `version` | print the version |

## Mailbox configuration

| Variable | Meaning |
| --- | --- |
| `PORT` | where to listen (default 8080) |
| `MAILBOX_STORE` | `mongo` in production; `memory` for local runs (refused on Cloud Run) |
| `MAILBOX_MONGO_URI` | a MongoDB connection string (Firestore's MongoDB mode works) |
| `MAILBOX_MONGO_DB` | the database name; defaults to the one in the URI's path |
| `MAILBOX_SETUP_TOKEN` | registers the first, admin computer; clear it afterwards |
| `MAILBOX_DEVICE_IDLE_DAYS` | phone keys unused this long stop working (default 30; `0` never) |
| `MAILBOX_TRUSTED_PROXIES` | CIDRs of front ends whose `X-Forwarded-For` entry names the client, for per-IP limits (default `66.249.64.0/19`, Firebase Hosting's edge) |
| `MAILBOX_DEBUG_ERRORS` | `1` returns store errors to callers, for diagnosis; otherwise they get a logged reference |
| `MAILBOX_WEB_DIR` | serves the phone app; the Docker image sets `/web` |

Health check: `GET /v1/health` returns `ok` once the store is connected,
and the error otherwise.

## Releases

CI (`.github/workflows/ci.yml`) runs the tests on every push, against a
real MongoDB, and builds `flow-remote` on macOS and the mailbox's Docker
image. To publish binaries, push a version tag:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` then builds `flow-remote` for macOS
(arm64, amd64) and the mailbox for Linux (amd64, arm64), stamps the
version, and attaches them with `checksums.txt` to a GitHub release.

## Development

```bash
go test ./...                       # includes WebCrypto interop tests under Node
node --test web/js/*.test.mjs       # the phone app's own tests (fuzzy search)
FLOW_REMOTE_MONGO_URI=mongodb://127.0.0.1:27017 go test ./internal/mailbox/   # the Mongo store

# A local mailbox with the app, in memory:
MAILBOX_SETUP_TOKEN=dev-token-dev-token-dev-token MAILBOX_WEB_DIR=web go run ./cmd/mailbox
```

For a test computer that doesn't touch your Keychain, set
`FLOW_REMOTE_KEYSTORE=dir FLOW_REMOTE_HOME=/tmp/fr`.

## License

MIT, see [LICENSE](LICENSE). The vendored libraries in `web/vendor` keep
their own licenses (jsQR: Apache-2.0, qrcode-generator: MIT); see
[web/vendor/VENDOR.md](web/vendor/VENDOR.md).
