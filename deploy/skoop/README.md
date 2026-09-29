# Deploy the mailbox with skoop

[skoop](https://skoop.facets.cloud) is one way to run the mailbox. It puts
it on GCP: Cloud Run for the container, Firestore (MongoDB-compatible) for
storage, and Firebase Hosting for TLS and an optional custom domain. The
mailbox itself is a plain container configured through environment
variables (see the main README), so any other host works too.
[`../docker`](../docker) is the self-hosted alternative.

Run everything from the **repo root**. skoop builds from the folder its
link lives in, and the Dockerfile is at the root. The link
(`.skoop/app.json`) holds your org's ids, so it isn't committed:
`skoop init` or `skoop link` creates it.

## First deploy

```bash
skoop init flow-remote            # or `skoop link flow-remote` for an existing app

# The token that registers your first (admin) computer. Keep a copy for
# `flow-remote setup`; skoop stores it write-only.
TOKEN=$(openssl rand -hex 24); echo "$TOKEN" > ~/.flow-remote-setup-token
skoop env set --secret MAILBOX_SETUP_TOKEN="$TOKEN"

skoop apply resource firestore -n mailbox --set deletion_policy=DELETE

skoop apply resource cloudrun --flavor cpu -n mailbox --source . \
  --set container.port=8080 \
  --set scaling.max_instances=1 --set scaling.concurrency=80 \
  --set resources.cpu=1000m --set resources.memory=256Mi --set timeout=60 \
  --set auth.allow_unauthenticated=true \
  --set env.MAILBOX_STORE=mongo \
  --set 'env.MAILBOX_MONGO_URI=${firestore.mailbox.out.attributes.connection_string}' \
  --set 'env.MAILBOX_SETUP_TOKEN=${blueprint.self.secrets.MAILBOX_SETUP_TOKEN}' \
  --set cloud_permissions.gcp.roles.firestore.role=roles/datastore.user

skoop apply resource firebase_hosting -n app \
  --set 'target_service=${cloudrun.mailbox.out.attributes.service_name}'

skoop builds create cloudrun/mailbox --remote
skoop plan
skoop releases create
skoop app status                  # the *.web.app URL
curl https://<your-url>/v1/health # "ok" once Firestore is connected
```

Then follow "Set up your computer" in the main README, using that URL.

## Custom domain

```bash
skoop apply resource firebase_hosting/app --set domain=flow.example.com
skoop releases create
skoop app status -o json          # firebase_hosting outputs: dns_records
```

Add the `dns_records` it lists (a CNAME to the `*.web.app` host, sometimes
an `_acme-challenge` TXT) at your DNS provider. The certificate usually
issues within about 10 minutes of the record resolving.

## Updating

```bash
skoop builds create cloudrun/mailbox --remote && skoop releases create
```

## After your first computer is set up

Switch the setup token off, so nobody can register an admin computer with it:

```bash
skoop env set --secret MAILBOX_SETUP_TOKEN=""   # or remove the env from the cloudrun resource
skoop releases create
```

Other computers join with `flow-remote invite`.

## Why these settings

- **`max_instances=1`.** Rate limits live in memory, and one small instance
  is plenty for one person or a small group.
- **`allow_unauthenticated=true`.** Firebase Hosting needs a public service.
  The mailbox checks a signature on every call instead of a login.
- **`MAILBOX_MONGO_URI` from Firestore.** Firestore's MongoDB mode accepts
  only its own database id as the Mongo database name, and that's the path
  of the connection string, so the mailbox uses it.
- **Health is `/v1/health`, not `/healthz`.** Google's front end reserves
  `/healthz`, so on Cloud Run that request never reaches the container.
- **Index creation is best effort.** The service account has no
  index-admin role, and Firestore Enterprise runs these queries without an
  index.
- **Cost.** Request-billed Cloud Run scales to zero, and relay polls are
  short requests, so a month of use fits the free tiers. Firestore bills
  per operation, and presence writes are capped at one every 20s per key.
