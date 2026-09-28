# Envelope protocol, v1

Every message between the phone and the Mac travels as one envelope. The
mailbox stores and forwards envelopes. It can read the routing fields and
nothing else, and it can't forge or alter an envelope without the receiver
noticing.

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
