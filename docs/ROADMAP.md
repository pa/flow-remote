# Roadmap

Tailscale is the one way flow-remote reaches your computer today. These are
the others we could add, and what each would take. A tunnel only carries
bytes: pairing, signed requests and sealed envelopes work the same over any
of them. What differs is who can change the app's code. That's whoever
ends TLS.

## Other ways to reach the computer

| Option | What it takes | Who ends TLS | Notes |
| --- | --- | --- | --- |
| **Headscale** (self-hosted Tailscale control server) | a `--control-url` flag passed to tsnet's `ControlURL` | your computer | The smallest change: same code path, no Tailscale account. You run the control server. |
| **Self-hosted relay** (`flow-remote tunnel` on a VPS, Cloud Run or Docker) | a relay command: the computer dials out over a WebSocket and phones reach it through the relay; `--tunnel relay` | the relay's host, or your computer with SNI passthrough on your own VPS | Designed on 2026-09-29, not built. Needs no VPN on the phone and keeps a custom domain. It would replace the hosted mailbox removed on 2026-09-30. |
| **Cloudflare Tunnel** | `--tunnel none --public-url` plus `cloudflared` pointed at `--listen`; docs | Cloudflare | Public, so the per-IP limits matter. Cloudflare Access can add a login in front. |
| **ngrok** with TLS passthrough | `--tunnel none`, with the certificate on the computer | your computer | Needs a paid ngrok plan for TLS endpoints and a reserved domain. |
| **NetBird, ZeroTier** and other WireGuard meshes | `--tunnel none` on the mesh address, with a certificate for it | your computer | Works if the mesh gives the phone a stable name and you can get a certificate for it. |
| **Home network only** | `--tunnel none` on a LAN address with a certificate | your computer | Nothing leaves the house, and nothing works away from it. |

A random quick-tunnel URL (ngrok free, `cloudflared` quick tunnels) doesn't
work for long. The phone's storage and pairing are tied to the app's
address, so each new URL means pairing again.

## Also open

- **Linux:** a key store (Secret Service, or a 0600 file) and a
  `systemd --user` service in place of the Keychain and launchd.
- **Read receipts and listener status**, once flow can report them
  ([Facets-cloud/flow#100](https://github.com/Facets-cloud/flow/issues/100)).
  Today the app infers "waiting" from replies.
- **Signed releases,** so `install.sh` and `flow-remote upgrade` check who
  built a release, not only that the download arrived intact.
- **A Face ID lock on sending** from the phone.
- **Reply notifications** with Web Push.
- **Load the QR scanner only when it's opened.** It's 251 KB of the app's
  412 KB cache.
- **Prune old messages** in the phone's storage.
- **A split view on wide screens.** On a tablet or a desktop window the app
  is a 640px phone column. From about 900px wide, the session list could
  sit beside the open chat, as chat apps do on an iPad.
