# Self-host the mailbox with Docker

Runs the mailbox, MongoDB and Caddy on any machine with Docker and a
public address. Caddy gets a TLS certificate automatically. The phone app
needs HTTPS, because WebCrypto and the camera only work on secure pages.

```bash
cd deploy/docker
cp .env.example .env
# DOMAIN: the name you'll use, with its DNS A/AAAA record pointing here
# MAILBOX_SETUP_TOKEN: openssl rand -hex 24 (keep a copy for flow-remote setup)
docker compose up -d
curl https://$DOMAIN/v1/health   # "ok" once MongoDB is connected
```

Then follow "Set up your computer" in the main README, with
`--mailbox https://$DOMAIN`.

Once your first computer is registered, clear `MAILBOX_SETUP_TOKEN` in `.env`
and run `docker compose up -d` again. Other computers join with
`flow-remote invite`.

MongoDB's data lives in the `mongo-data` volume. It holds sealed envelopes
(deleted on delivery or after 7 days), public keys and last-seen times, and
no message text or private keys.
