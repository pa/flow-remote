# Envelope protocol, v1

Every message between the phone and the computer travels as one envelope.
Whatever carries envelopes (the server in `flow-remote run`, and
Tailscale in between) can read the routing fields and nothing else. It can't forge or
alter an envelope without the receiver noticing.

Field names say `mac` (`mac_id`, `mac_sign_pub`) for the computer's side.
That's the name the protocol started with. It's kept so existing pairings
keep working, and it means any computer, not only a Mac.

Two implementations must agree on every byte:
`internal/envelope/envelope.go` (Mac) and `web/js/envelope.js` (phone).
`go test ./internal/envelope` runs the JavaScript under Node and checks both
directions.

## Keys

Each party holds two P-256 key pairs. WebCrypto won't use one key for both
signing and key agreement.

| Key | Algorithm | Used for |
| --- | --- | --- |
| sign | ECDSA P-256, SHA-256 | signing envelopes it sends |
| box | ECDH P-256 | receiving envelopes sealed to it |

Public keys travel as the uncompressed SEC1 point (65 bytes, WebCrypto's
`raw` export), base64url without padding. On the phone both private keys are
non-extractable `CryptoKey`s in IndexedDB. On the Mac they're in the
Keychain.

## Envelope

```json
{
  "v": 1,
  "id": "<16 random bytes>",
  "from": "<sender id>",
  "to": "<recipient id>",
  "ts": 1790610574000,
  "epk": "<ephemeral ECDH public key>",
  "ct": "<12-byte nonce || AES-GCM ciphertext || 16-byte tag>",
  "sig": "<ECDSA r || s, 64 bytes>"
}
```

Every binary field is base64url without padding. `ts` is the sender's clock
in unix milliseconds.

## Sealing

1. Generate an ephemeral ECDH P-256 key pair `eph`.
2. `shared = ECDH(eph.private, recipient.box_pub)`, the 32-byte x coordinate.
3. `key = HKDF-SHA256(ikm = shared, salt = empty, info = "flow-remote/v1" || eph.pub || recipient.box_pub, 32 bytes)`.
4. `header = "flow-remote/v1\n" + v + "\n" + id + "\n" + from + "\n" + to + "\n" + ts`.
5. `ct = nonce || AES-256-GCM(key, nonce, plaintext, aad = header)`, with a
   random 12-byte nonce.

The header sits in the GCM tag, so a ciphertext can't be moved under
another header even if a signature check were skipped.

## Signing

`sig = ECDSA-P256-SHA256(sender.sign_priv, header + "\n" + epk + "\n" + ct)`,
encoded as raw `r || s` (32 bytes each), the format WebCrypto produces.

## Receiving

In this order:

1. Reject if `v` isn't 1.
2. Look up `from` among enrolled devices. Reject if it's unknown or revoked.
3. Verify `sig`. Reject on failure. Don't trust any field before this.
4. Replay guard: reject if `ts` is more than 5 minutes ahead of the local
   clock, more than 7 days old, or if `id` was already seen. Accepted ids
   are kept for 7 days, the mailbox's retention, so a replay is caught at
   any age. A message that waited while the Mac slept is still accepted,
   and the session is told how old it is.
5. Open `ct` with the box key.

The guard only records an id after the signature check, so a forger can't
use up ids that real messages would later need.

## Requests to the mailbox

Nobody signs in. Every call to the mailbox is signed, except the phone's
single pairing post, and the mailbox only ever holds public keys.

| Header | Value |
| --- | --- |
| `X-FR-Key` | the signer's id: `mac-…` or `dev-…` |
| `X-FR-TS` | the signer's clock, unix milliseconds; rejected if more than 2 minutes off |
| `X-FR-Sig` | ECDSA P-256 over `"flow-remote/v1 req\n" + method + "\n" + path_with_query + "\n" + ts + "\n" + hex(sha256(body))`, raw `r \|\| s` |

`internal/reqsig` (Go) and `web/js/api.js` (WebCrypto) produce the same
signature, and `go test ./internal/reqsig` checks it.

Keys reach the server in this order:

1. **The computer is registered** in the server's store when
   `flow-remote run` starts, as its only tenant.
2. **The computer opens a pairing slot.** `flow-remote pair` opens a slot
   for the offer's pair id. The phone posts its enrollment into it, which
   is the only unsigned call. The server accepts it only if the envelope is
   addressed to this computer. A slot takes one enrollment, expires after
   2 minutes, and only the computer can collect it.
3. **The computer registers the device** once you confirm the fingerprint.
   The server then accepts requests signed by its key. `flow-remote revoke`
   revokes it there too, and a revoked id can't be registered again.

A device sends only as itself, only to the computer, and reads only its
own queue. Ids are also checked by prefix: a device key can't call the
computer's routes, which only the unix socket serves anyway.

## Pairing offer

The QR code encodes `<app URL>/#pair=<base64url JSON>`. The fragment never
reaches a server.

| Field | Meaning |
| --- | --- |
| `v` | 1 |
| `mac_id`, `mac_sign_pub`, `mac_box_pub` | the computer's id and public keys; the phone pins these |
| `pair_id` | the slot the enrollment goes into |
| `secret` | 16 random bytes; the phone HMACs its enrollment with it |
| `exp` | expiry, unix ms (2 minutes) |
| `mailbox` | where this computer's API is, when it isn't the app's own origin (https only); empty otherwise |

## Messages inside envelopes

The plaintext of every envelope after pairing is one JSON object with a
`kind`. `internal/protocol` and `web/js/app.js` speak the same fields.

| Kind | Direction | Fields |
| --- | --- | --- |
| `send` | phone → computer | `client_id` (the phone's id for its bubble), `task` (slug), `body` (1–4000 characters), `reply_to` (a flow message id this answers, optional) |
| `sync` | phone → computer | none; asks for a fresh session list |
| `paired` | computer → phone | `mac_name`; pairing is confirmed |
| `sessions` | computer → phone | `sessions`: `slug`, `name`, `project`, `tags`, `waiting_on`, `can_send` (always true since the allowlist was removed) |
| `status` | computer → phone | `client_id`, `task`, `state` (`delivered`, `refused`, `failed`, `stale`), `reason`, `flow_id` (the id flow gave the message) |
| `mail` | computer → phone | `mail`: `flow_id`, `task`, `body`, `urgent`, `broadcast`, `created_at`, `reply_to` (the flow id of the message it answers) |

The relay accepts a `send`'s `reply_to` only if it's a message it
forwarded from that same session. With a valid one it runs
`flow message user/<slug> --reply-to <id>` and marks that message read.
A `send` whose envelope is more than 10 minutes old comes back `stale` and
isn't delivered. The phone offers to send it again.

The phone links a `mail`'s `reply_to` to the `flow_id` of its own message,
to show which message a reply answers.

## Serving from the computer

`flow-remote run`, with a tunnel set up, runs the mailbox server in the
same process. The routes and signatures are the ones above.

- **The tunnel's listener** (Tailscale: `:443` on the tsnet device, with
  TLS ending in the process) serves the app's files and the phone's
  routes only: `/v1/pair/{pair}`, `/v1/envelopes`, `/v1/ack`,
  `/v1/status` and `/v1/health`. `/v1/macs` and `/v1/relay/*` get a 404
  there. `X-Forwarded-For` is ignored, so every client is limited by its
  own address.
- **The unix socket** `~/.flow-remote/mailbox.sock` (mode 0600) serves
  every route. The relay and the CLI (`pair`, `devices`, `revoke`) use it,
  signing as the computer.
- **CORS** allows the app origins set with `setup --app`, so an app
  installed from one computer can reach another's API. Signatures, not the
  origin, authenticate requests.
