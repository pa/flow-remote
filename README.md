# flow-remote

Message your [flow](https://github.com/Facets-cloud/flow) sessions from your
phone, and get their replies back, through a mailbox that can't read or
forge anything.

```
 phone (web app)            mailbox (any host)              your Mac
 a key per Mac  ──HTTPS──▶  stores sealed envelopes  ◀──  flow-remote relay
 seals + signs              checks signatures,              opens, checks,
 every message              knows only public keys          runs `flow message`
```

- **End to end.** Every message is sealed to its recipient (P-256 ECDH,
  AES-256-GCM) and signed by its sender (P-256 ECDSA). The mailbox sees who
  talks to whom and when, and nothing else.
- **No accounts.** Macs and phones prove who they are by signing each
  request. The mailbox holds only public keys.
- **Tenants.** Each Mac is its own tenant. A phone belongs to the Mac that
  paired it and can only reach that Mac. Your other Macs, and other
  people's, are separate.
- **Per-device revocation.** `flow-remote revoke` cuts off one phone. Its
  key signs nothing afterwards.

Details: [docs/DESIGN.md](docs/DESIGN.md) covers the architecture,
decisions and prior art, and [docs/PROTOCOL.md](docs/PROTOCOL.md) the byte
formats.

## 1. Run a mailbox

The mailbox is one container: the API plus the phone app. Pick a host:

- **[deploy/skoop](deploy/skoop)**: Cloud Run, Firestore and Firebase
  Hosting on GCP, including a custom domain.
- **[deploy/docker](deploy/docker)**: Docker Compose with MongoDB and Caddy
  on any machine.
- **Anything else** that runs a container over HTTPS: see
  [Mailbox configuration](#mailbox-configuration).

Keep the `MAILBOX_SETUP_TOKEN` you set. Your first Mac needs it.

## 2. Set up your Mac

Needs Go and [flow](https://github.com/Facets-cloud/flow).

```bash
git clone https://github.com/pa/flow-remote && cd flow-remote
go install ./cmd/flow-remote                 # installs to $(go env GOPATH)/bin

# Your first Mac on this mailbox: the setup token makes it the admin.
FLOW_REMOTE_SETUP_TOKEN=<token> flow-remote setup --mailbox https://flow.example.com --name "Work Mac"
```

Keys go in the login Keychain (service `flow-remote`). Settings and logs
go in `~/.flow-remote/`.

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
2. On the Mac, run `flow-remote pair`. It shows a QR code for 2 minutes
   (`--png FILE` saves it as an image as well).
3. In the app, tap **Scan the QR code**, or **Take a photo of the QR code**
   if the live camera won't start. Then tap **Pair**.
4. Check that the fingerprints on the two screens match, and type `y` on
   the Mac.

The phone now lists your live sessions. Sessions in
`~/.flow-remote/allow.txt` accept messages; the rest are read-only:

```
phone-dispatch     # a task slug
#personal          # every live task with this tag
*                  # every live session
```

The relay reads this file when it starts, so run `flow-remote start` again
after changing it.

## 5. More Macs, yours or anyone's

On an admin Mac:

```bash
flow-remote invite        # a single-use code, valid for 24 hours
```

On the new Mac, after installing:

```bash
FLOW_REMOTE_INVITE=<code> flow-remote setup --mailbox https://flow.example.com --name "Home Mac"
flow-remote start && flow-remote pair
```

Pair from the same phone with **Settings → Pair another Mac**. The app
keeps a separate key per Mac and shows a switcher.

Admin commands: `flow-remote tenants` lists Macs, and
`flow-remote remove-tenant <mac-id>` removes one, together with its phones
and its mail.

Once your first Mac is set up, clear `MAILBOX_SETUP_TOKEN` on the mailbox.
Invites cover everything after that.

## Commands

| Command | What it does |
| --- | --- |
| `setup --mailbox URL [--name N]` | save the mailbox and register this Mac (`FLOW_REMOTE_SETUP_TOKEN` or `FLOW_REMOTE_INVITE`) |
| `start` / `stop` / `status` | run the relay as a launchd agent, stop it, check it |
| `run` | run the relay in the foreground |
| `pair [--png FILE]` | show a QR code and enroll a phone |
| `devices [--all]` / `revoke <device-id>` | list this Mac's active phones with when each last checked in (`--all` adds revoked ones), or cut one off |
| `invite` | (admin) a single-use code for another Mac |
| `tenants` / `remove-tenant <mac-id>` | (admin) list or remove Macs |

## Mailbox configuration

| Variable | Meaning |
| --- | --- |
| `PORT` | where to listen (default 8080) |
| `MAILBOX_STORE` | `mongo` in production; `memory` for local runs (refused on Cloud Run) |
| `MAILBOX_MONGO_URI` | a MongoDB connection string (Firestore's MongoDB mode works) |
| `MAILBOX_MONGO_DB` | the database name; defaults to the one in the URI's path |
| `MAILBOX_SETUP_TOKEN` | registers the first, admin Mac; clear it afterwards |
| `MAILBOX_DEVICE_IDLE_DAYS` | phone keys unused this long stop working (default 30; `0` never) |
| `MAILBOX_WEB_DIR` | serves the phone app; the Docker image sets `/web` |

Health check: `GET /v1/health` returns `ok` once the store is connected,
and the error otherwise.

## Development

```bash
go test ./...                       # includes WebCrypto interop tests under Node
node --test web/js                  # the phone app's own tests (fuzzy search)
FLOW_REMOTE_MONGO_URI=mongodb://127.0.0.1:27017 go test ./internal/mailbox/   # the Mongo store

# A local mailbox with the app, in memory:
MAILBOX_SETUP_TOKEN=dev-token-dev-token-dev-token MAILBOX_WEB_DIR=web go run ./cmd/mailbox
```

For a test Mac that doesn't touch your Keychain, set
`FLOW_REMOTE_KEYSTORE=dir FLOW_REMOTE_HOME=/tmp/fr`.
