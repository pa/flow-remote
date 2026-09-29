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

`flow-remote setup` shows these same steps one at a time in the terminal
and waits for you to finish each, so you can follow along there instead.

Everything here is in the [Tailscale admin console](https://console.tailscale.com/admin),
as an Owner or Admin of the tailnet. It takes three settings: DNS with
HTTPS, a tag in the policy file, and an auth key with that tag. Do them in
this order, because the key's tag has to exist first.

### 1a. Turn on MagicDNS and HTTPS certificates

1. Open **DNS** ([console.tailscale.com/admin/dns](https://console.tailscale.com/admin/dns)).
2. If MagicDNS is off, select **Enable MagicDNS**.
3. Under **HTTPS Certificates**, select **Enable HTTPS** and accept the
   notice.

The app needs HTTPS to install on the phone and to use the camera.

**Read the notice before you accept it.** Every HTTPS certificate is
recorded in public Certificate Transparency logs. So the device name
`flow-remote-<name>` and your tailnet's name (`<tailnet>.ts.net`) become
public. Pick a `--name` in step 2 that says nothing sensitive: not a
customer, client or project.

### 1b. Add the tag and who can reach it

1. Open **Access controls**
   ([console.tailscale.com/admin/acls](https://console.tailscale.com/admin/acls))
   and switch to the JSON editor, which shows the tailnet policy file.
2. Add `tag:flow-remote` under `tagOwners`, creating that section if it
   isn't there. This says who may put the tag on a device: admins of the
   tailnet.
3. Add a rule under `grants` that lets your own devices reach it on port 443
   only.
4. Select **Save**.

After the edit, the relevant parts look like this. Keep your other
entries, and add these alongside them:

```json
{
  "tagOwners": {
    "tag:flow-remote": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["tag:flow-remote"],
      "ip":  ["tcp:443"]
    }
  ]
}
```

- `autogroup:member` is every user of the tailnet. On a personal tailnet
  that's you. To be stricter, list your own login instead, like
  `"you@example.com"`.
- A new tailnet's default policy allows every device to reach every other
  on any port. With that rule still in place, the grant above changes
  nothing, because everything is already allowed. flow-remote only listens
  on 443 either way. To limit it, replace the allow-all rule with rules for
  what you actually use.
- The tagged device gets no access to your other devices unless a rule
  grants it. Nothing above does.

Tailscale rejects the save with a message if the file has a mistake. Tag
names are case-insensitive, so `tag:Flow-Remote` is the same tag.

### 1c. Create the auth key

1. Open **Settings > Keys**
   ([console.tailscale.com/admin/settings/keys](https://console.tailscale.com/admin/settings/keys))
   and select **Generate auth key**.
2. Fill in the form:
   - **Description:** something like `flow-remote on my laptop`.
   - **Reusable:** off. One key joins one device.
   - **Expiration:** 1 day. It only has to work until you run setup.
   - **Ephemeral:** off. An ephemeral device disappears when it goes
     offline, and it would when your computer sleeps.
   - **Tags:** on, and choose `tag:flow-remote`. If it isn't in the list,
     step 1b wasn't saved.
   - **Pre-approved:** on. It only shows if device approval is on for your
     tailnet, and it lets the device join without a manual approval.
3. Select **Generate key** and copy the key, which starts with
   `tskey-auth-`. Treat it like a password until you've used it. It's shown
   once.

Tagged devices belong to the tailnet rather than to a person, so their
node key doesn't expire after 180 days the way a person's devices do.

## 2. Set up the computer

```bash
flow-remote setup --name "My laptop"      # --tunnel tailscale is the default
```

Paste the auth key when asked. Input is hidden. To script it, set
`TS_AUTHKEY` instead, or pipe the key in. Setup joins the tailnet, fetches
the HTTPS certificate once, and prints the address phones will use. The key
isn't saved. After the first join the device's identity lives in
`~/.flow-remote/tailscale`, which is created with mode 0700.

The name becomes part of the app's address, and the phone's storage is
tied to that address. So choose it once: running setup again keeps the
name it already has. The name also becomes public through the certificate
logs (see 1a).

To check it worked, open **Machines** in the admin console. You should see
`flow-remote-<name>` with the `tag:flow-remote` tag. Its expiry column
should say key expiry is disabled, which is normal for tagged devices.

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
