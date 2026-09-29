# Serve from your computer over Tailscale

With this setup there's no server to deploy. `flow-remote` runs on your computer,
joins your tailnet as its own device, and serves the phone app and its API
at `https://flow-remote-<name>.<tailnet>.ts.net`. Your phone reaches it
through the Tailscale app.

```
 phone (web app) ──Tailscale──▶ flow-remote on your computer ──▶ flow sessions
 Tailscale app on               its own tailnet device,
                                one HTTPS port
```

## What it exposes

`flow-remote` embeds Tailscale's Go library, tsnet. tsnet runs its own
network stack inside the `flow-remote` process:

- The computer gets no VPN interface and no routes. The Tailscale app isn't
  needed on the computer, and nothing else on the computer (SSH, file sharing, dev
  servers) becomes reachable.
- The device answers on port 443 only. Every API request there must be
  signed by a phone you paired and confirmed on the computer. Anything else gets
  a 401 before it reaches `flow`.
- TLS ends inside `flow-remote`, so only your computer can serve or change the
  app's code.
- It runs as your user, not root. Tailscale SSH, exit node and subnet
  routes stay off.

The computer has to be awake for messages to go through. While it's asleep the
app still opens from the phone's cache. It shows the computer as unreachable and
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

## 2. Set up the computer

```bash
flow-remote setup --name "My laptop"      # --tunnel tailscale is the default
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
flow-remote start      # in the background: runs at login, restarts if it crashes
flow-remote status     # the address phones use, and the last log lines
flow-remote pair       # shows a QR code
```

## 3. Set up the phone

1. Install the Tailscale app, sign in to the same tailnet, and turn it on.
2. On an iPhone, the first scan with the camera opens Safari. It shows how
   to add flow-remote to your Home Screen. Do that, open the app from the
   Home Screen, and scan again from inside it. An installed app keeps its
   storage apart from Safari, and the keys have to live in the app. On
   Android you can pair in the browser.
3. Check that the fingerprints match, and type `y` on the computer.

Tailscale on the phone only carries traffic for your tailnet. If
everything seems to go through it, check that no exit node is selected in
the app, and that **Override local DNS** is off on the admin console's
DNS page. iOS runs one VPN at a time, so a work VPN on the phone will get
in its way.

When the app can't reach the computer, it says why, as far as it can
tell. A tailnet name isn't in public DNS, so with Tailscale off on the
phone the request fails at once and the app asks "Is Tailscale on?". A
computer that's asleep or not running `flow-remote` doesn't answer, and
the app says so after 10 seconds.

## Removing it

- To cut the device off at once, remove it under **Machines** in the admin
  console.
- To start over, run `flow-remote stop`, delete `~/.flow-remote/tailscale`,
  generate a new key, and run setup again.
- With [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock), every new
  device must be signed from one of your trusted devices before it can join.
  That stops Tailscale's coordination server from adding a device to your
  tailnet on its own.
