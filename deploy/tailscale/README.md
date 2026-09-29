# Serve from your Mac over Tailscale

With this setup there's no server to deploy. `flow-remote` runs on your Mac,
joins your tailnet as its own device, and serves the phone app and its API
at `https://flow-remote-<name>.<tailnet>.ts.net`. Your phone reaches it
through the Tailscale app.

```
 phone (web app) ──Tailscale──▶ flow-remote on your Mac ──▶ flow sessions
 Tailscale app on               its own tailnet device,
                                one HTTPS port
```

## What it exposes

`flow-remote` embeds Tailscale's Go library, tsnet. tsnet runs its own
network stack inside the `flow-remote` process:

- The Mac gets no VPN interface and no routes. The Tailscale app isn't
  needed on the Mac, and nothing else on the Mac (SSH, file sharing, dev
  servers) becomes reachable.
- The device answers on port 443 only. Every API request there must be
  signed by a phone you paired and confirmed on the Mac. Anything else gets
  a 401 before it reaches `flow`.
- TLS ends inside `flow-remote`, so only your Mac can serve or change the
  app's code.
- It runs as your user, not root. Tailscale SSH, exit node and subnet
  routes stay off.

The Mac has to be awake for messages to go through. While it's asleep the
app still opens from the phone's cache. It shows the Mac as unreachable and
keeps what you type for up to 10 minutes.

## 1. Prepare the tailnet (once)

In the [Tailscale admin console](https://login.tailscale.com/admin):

1. On the **DNS** page, turn on **MagicDNS** and **HTTPS Certificates**. The
   app needs HTTPS to install and to use the camera.
2. In **Access controls**, add a tag and a rule letting only your own
   devices reach it, only on 443. Merge this into your policy:

   ```json
   {
     "tagOwners": { "tag:flow-remote": ["autogroup:admin"] },
     "grants": [
       { "src": ["autogroup:member"], "dst": ["tag:flow-remote"], "ip": ["tcp:443"] }
     ]
   }
   ```

   If your policy still has the default rule that allows everything, other
   devices can reach the node on any port. flow-remote only listens on 443,
   but the rule above is tighter. The node gets no access to your other
   devices unless a rule grants it.
3. In **Settings > Keys**, generate an auth key with these settings:
   - reusable **off**
   - ephemeral **off**
   - pre-approved **on**
   - tag **`tag:flow-remote`**
   - a short expiry, such as a day

   The key is used once. Tagged devices don't expire after 180 days the
   way devices logged in by a person do.

## 2. Set up the Mac

```bash
flow-remote setup --tunnel tailscale --name "My Mac"
```

Paste the auth key when asked. Input is hidden. To script it, set
`TS_AUTHKEY` instead, or pipe the key in. Setup joins the tailnet, fetches
the HTTPS certificate once, and prints the address phones will use. The key
isn't saved. After the first join the device's identity lives in
`~/.flow-remote/tailscale`, which is created with mode 0700.

The name becomes part of the app's address, and the phone's storage is tied
to that address. So choose it once: running setup again keeps the name it
already has.

Then:

```bash
flow-remote start      # runs at login, restarts if it crashes
flow-remote pair       # shows a QR code
```

## 3. Set up the phone

Install the Tailscale app, sign in to the same tailnet, and turn it on. Scan
the QR code and check that the fingerprints match. Then add the app to your
Home Screen.

iOS runs one VPN at a time. If your phone also needs a work VPN, the two
will get in each other's way.

## Removing it

- To cut the device off at once, remove it under **Machines** in the admin
  console.
- To start over, run `flow-remote stop`, delete `~/.flow-remote/tailscale`,
  generate a new key, and run setup again.
- With [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock), every new
  device must be signed from one of your trusted devices before it can join.
  That stops Tailscale's coordination server from adding a device to your
  tailnet on its own.
