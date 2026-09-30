// Command flow-remote serves your flow sessions to your phone: it sets up
// this computer, pairs phones, and runs the server that carries messages
// between phones and flow sessions. Phones reach it over your tailnet.
//
//	flow-remote setup [--name N] [--app URL]
//	                                      join your tailnet (--tunnel tailscale,
//	                                      the default); asks for a single-use
//	                                      auth key tagged tag:flow-remote
//	flow-remote setup --tunnel none --listen ADDR --public-url URL
//	                                      serve on ADDR; you route URL to it
//	                                      (for tests, and localhost)
//	flow-remote pair [--png FILE]         show a QR code (and optionally save it
//	                                      as an image) and enroll a phone
//	flow-remote run                       serve in the foreground
//	flow-remote start | stop | status     run it as a launchd agent (at login,
//	                                      restarted on crash), stop it, check it
//	flow-remote upgrade                   install the latest release in place
//	flow-remote devices [--all]           list enrolled phones
//	flow-remote revoke <device-id>        stop trusting a phone
//
// Keys and the device list live in the login Keychain under "flow-remote".
// Everything else is in ~/.flow-remote.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"rsc.io/qr"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/flowcli"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/keystore"
	"github.com/pa/flow-remote/internal/pairing"
	"github.com/pa/flow-remote/internal/protocol"
	"github.com/pa/flow-remote/internal/relay"
	"github.com/pa/flow-remote/internal/serve"
	"github.com/pa/flow-remote/internal/tunnel"
)

// version is set at release build time (-ldflags "-X main.version=v1.2.3").
var version = "dev"

type config struct {
	Tunnel    string   `json:"tunnel,omitempty"`     // how phones reach this computer: tailscale or none
	Hostname  string   `json:"hostname,omitempty"`   // tunnel "tailscale": the tailnet device name
	Listen    string   `json:"listen,omitempty"`     // tunnel "none": where to listen
	PublicURL string   `json:"public_url,omitempty"` // tunnel "none": what phones use
	Origins   []string `json:"origins,omitempty"`    // other app addresses allowed to call this one
	Mailbox   string   `json:"mailbox,omitempty"`    // set by versions with a hosted mailbox; no longer used
	App       string   `json:"app,omitempty"`
	Name      string   `json:"name,omitempty"` // what phones call this Mac
}

// mailboxClient reaches this computer's mailbox, on the running server's
// socket.
func mailboxClient(_ config, mac *identity.Mac) *client.Client {
	return serve.Client(home(), mac)
}

// explain turns "nothing on the socket" into what to do about it.
func explain(err error) error {
	if serve.NotRunning(err) {
		return serve.ErrNotRunning
	}
	return err
}

// servedURL is the address the running serve reported for phones.
func servedURL() (string, error) {
	b, err := os.ReadFile(filepath.Join(home(), "serve.json"))
	if err != nil {
		return "", serve.ErrNotRunning
	}
	var v struct {
		URL string `json:"url"`
	}
	return v.URL, json.Unmarshal(b, &v)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("flow-remote", version)
		return
	case "setup":
		err = setup(os.Args[2:])
	case "pair":
		err = pair(ctx, os.Args[2:])
	case "run":
		err = run(ctx)
	case "start":
		err = agentStart()
	case "stop":
		err = agentStop()
	case "status":
		err = agentStatus()
	case "upgrade":
		err = upgrade(ctx, os.Args[2:])
	case "devices":
		err = devices(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "flow-remote:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: flow-remote <command>
  setup [--name N]                  serve this computer's phones over your tailnet (asks for a Tailscale auth key)
  start | stop | status             run in the background (launchd), stop, check
  run                               run in the foreground
  pair [--png FILE]                 show a QR code and enroll a phone
  devices [--all] | revoke <id>     list this computer's phones (--all: with revoked), or revoke one
  upgrade [--check]                 install the latest release in place (--check: only say if there's one)
  version                           print the version`)
	os.Exit(2)
}

func home() string {
	if d := os.Getenv("FLOW_REMOTE_HOME"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".flow-remote")
}

func store() keystore.Store {
	if os.Getenv("FLOW_REMOTE_KEYSTORE") == "dir" {
		return keystore.Dir{Path: filepath.Join(home(), "keys")}
	}
	return keystore.Keychain{Service: "flow-remote"}
}

func loadConfig() (config, error) {
	var c config
	b, err := os.ReadFile(filepath.Join(home(), "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, errors.New("run `flow-remote setup` first")
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Tunnel == "" {
		return c, errors.New("this computer was set up for the hosted mailbox, which is gone; run `flow-remote setup` to serve over Tailscale")
	}
	return c, nil
}

func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	tun := fs.String("tunnel", "", "serve phones from this machine through this tunnel: tailscale or none")
	listen := fs.String("listen", "127.0.0.1:8484", "tunnel none: address to listen on")
	public := fs.String("public-url", "", "tunnel none: the https URL phones use to reach --listen")
	app := fs.String("app", "", "the phone app to pair from, if it's another computer's (default: this one's)")
	name := fs.String("name", "", "what phones call this computer (default: its hostname)")
	fs.Parse(args)
	if *tun == "" {
		*tun = "tailscale"
	}
	return setupLocal(*tun, *listen, *public, *app, *name)
}

// setupLocal saves the settings for serving from this computer. Nothing to
// register: `run` makes this computer the only tenant of its own mailbox.
func setupLocal(tun, listen, public, app, name string) error {
	switch tun {
	case "tailscale":
		return setupTailscale(app, name)
	case "none":
	default:
		return fmt.Errorf("--tunnel %q: want tailscale or none", tun)
	}
	// Browsers treat localhost as secure, so http is fine there for trying
	// it out; anywhere else the app needs https to install and use the
	// camera.
	if !strings.HasPrefix(public, "https://") && !strings.HasPrefix(public, "http://localhost:") && !strings.HasPrefix(public, "http://127.0.0.1:") {
		return errors.New("--public-url must be the https address phones use; the app needs HTTPS to install and to use the camera")
	}
	c := config{Tunnel: tun, Listen: listen, PublicURL: strings.TrimRight(public, "/"), App: strings.TrimRight(app, "/"), Name: name}
	if err := writeConfig(c); err != nil {
		return err
	}
	mac, err := identity.LoadOrCreateMac(store())
	if err != nil {
		return err
	}
	fmt.Printf("saved. This computer is %s, fingerprint %s\n", mac.ID, mac.Fingerprint())
	fmt.Printf("flow-remote will listen on %s. Route %s to it, with TLS ending on this machine\n", listen, c.PublicURL)
	fmt.Println("or a proxy you run: whoever ends TLS can change the app's code.")
	fmt.Println("Next: `flow-remote start`, then `flow-remote pair`.")
	return nil
}

func tailscaleDir() string { return filepath.Join(home(), "tailscale") }

// setupTailscale joins this machine to the tailnet as its own device. The
// auth key comes from TS_AUTHKEY or a hidden prompt, never a flag, so it
// stays out of shell history and the process list, and it isn't saved:
// after the first join the device's identity is in ~/.flow-remote/tailscale.
func setupTailscale(app, name string) error {
	name, host := tailnetName(name)
	ts := &tunnel.Tailscale{Dir: tailscaleDir(), Hostname: host, Logf: func(f string, a ...any) { fmt.Printf(f+"\n", a...) }}
	if !tunnel.Joined(ts.Dir) {
		key, err := authKey(host)
		if err != nil {
			return err
		}
		ts.AuthKey = key
	}
	fmt.Printf("joining the tailnet as %s...\n", host)
	url, err := ts.Join(context.Background())
	if err != nil {
		return err
	}
	c := config{Tunnel: "tailscale", Hostname: host, App: strings.TrimRight(app, "/"), Name: name}
	if err := writeConfig(c); err != nil {
		return err
	}
	mac, err := identity.LoadOrCreateMac(store())
	if err != nil {
		return err
	}
	fmt.Printf("saved. This computer is %s, fingerprint %s\n", mac.ID, mac.Fingerprint())
	fmt.Printf("Phones on your tailnet will reach it at %s\n", url)
	fmt.Println("Next: `flow-remote start`, then `flow-remote pair`.")
	return nil
}

// tailnetName returns the computer's display name (the host name when name
// is empty) and its device name on the tailnet. A computer that already
// joined keeps its device name: it's part of the app's address, and a new
// one means pairing every phone again.
func tailnetName(name string) (display, host string) {
	if name == "" {
		name, _ = os.Hostname()
		name = strings.TrimSuffix(name, ".local")
	}
	if prev, err := loadConfig(); err == nil && prev.Tunnel == "tailscale" && prev.Hostname != "" {
		return name, prev.Hostname
	}
	return name, tunnel.Hostname(name)
}

// authKey returns the Tailscale auth key from TS_AUTHKEY, or else asks for
// it, after walking through the admin console when stdin is a terminal.
func authKey(host string) (string, error) {
	key := os.Getenv("TS_AUTHKEY")
	if key == "" {
		interactive := term.IsTerminal(int(os.Stdin.Fd()))
		if interactive {
			if err := tailnetGuide(host); err != nil {
				return "", err
			}
		}
		fmt.Print("Paste the auth key (input hidden): ")
		b, err := readSecret(interactive)
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("reading the key: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if !strings.HasPrefix(key, "tskey-") {
		return "", errors.New("that doesn't look like a Tailscale auth key (tskey-...)")
	}
	return key, nil
}

// readSecret reads one line from stdin without echoing it at a terminal.
// Piped in (from a password manager's CLI, say), it reads the first line.
func readSecret(interactive bool) ([]byte, error) {
	if interactive {
		return term.ReadPassword(int(os.Stdin.Fd()))
	}
	b, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return b, err
}

// tailnetGuide walks through the admin console before asking for the key,
// one step at a time. It only runs at a terminal: with TS_AUTHKEY set or a
// key piped in, setup goes straight on.
func tailnetGuide(host string) error {
	in := bufio.NewReader(os.Stdin)
	steps := []struct{ title, body string }{
		{"Turn on MagicDNS and HTTPS certificates", `Open https://console.tailscale.com/admin/dns
  - If MagicDNS is off, select Enable MagicDNS.
  - Under HTTPS Certificates, select Enable HTTPS and accept the notice.

HTTPS certificates are published in public Certificate Transparency logs,
so this computer's address will be public:
    ` + host + `.<your-tailnet>.ts.net
If that name says too much (a customer, a project), press Ctrl-C and run
setup again with a different --name.`},
		{"Add the tag, and who can reach it", `Open https://console.tailscale.com/admin/acls and switch to the JSON editor.
Add these next to what's already there, then select Save:

    "tagOwners": {
      "tag:flow-remote": ["autogroup:admin"]
    },
    "grants": [
      { "src": ["autogroup:member"], "dst": ["tag:flow-remote"], "ip": ["tcp:443"] }
    ]

Only your own devices reach this computer, and only on port 443. If the
file already has a "grants" or "tagOwners" section, add the entries inside
it rather than a second one.`},
		{"Create the auth key", `Open https://console.tailscale.com/admin/settings/keys and select
Generate auth key, with:
  - Reusable:      off   (one key, one device)
  - Expiration:    1 day (it's only needed now)
  - Ephemeral:     off   (it would vanish whenever the computer sleeps)
  - Tags:          on, tag:flow-remote   (missing? step 2 wasn't saved)
  - Pre-approved:  on, if it's shown
Select Generate key and copy it. It starts with tskey-auth- and is shown once.
The key is for this computer only. Sign your phone in to Tailscale with your
own account, never with this key: a tagged phone can't reach flow-remote.`},
	}
	fmt.Println("\nflow-remote joins your tailnet as its own device. First, three settings in")
	fmt.Println("the Tailscale admin console (you need to be an Owner or Admin there).")
	fmt.Println("Already done? Just press Enter through them.")
	for i, st := range steps {
		fmt.Printf("\n%d of %d. %s\n\n%s\n\nPress Enter when done: ", i+1, len(steps), st.title, st.body)
		if _, err := in.ReadString('\n'); err != nil {
			return errors.New("stopped")
		}
	}
	fmt.Println()
	return nil
}

func writeConfig(c config) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(home(), "config.json"), b, 0o600)
}

func pair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	png := fs.String("png", "", "also write the QR code to this PNG file")
	fs.Parse(args)
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ks := store()
	mac, err := identity.LoadOrCreateMac(ks)
	if err != nil {
		return err
	}
	devs, err := identity.LoadDevices(ks)
	if err != nil {
		return err
	}
	mb := mailboxClient(cfg, mac)

	appURL, mailboxURL, err := pairingURLs(cfg)
	if err != nil {
		return err
	}
	offer := pairing.NewOffer(mac, mailboxURL, time.Now())
	if err := mb.OpenPair(ctx, offer.PairID); err != nil {
		return fmt.Errorf("opening the pairing: %w", explain(err))
	}
	if err := showOffer(offer.Link(appURL), *png, mac); err != nil {
		return err
	}
	dev, err := waitForPhone(ctx, mb, offer, mac)
	if err != nil {
		return err
	}
	if !confirm(fmt.Sprintf("\nPhone: %q\nIts fingerprint: %s\nDoes that match the fingerprint on the phone's screen? Enroll it? [y/N] ", dev.Name, dev.Fingerprint())) {
		return errors.New("not enrolled")
	}
	if err := devs.Enroll(dev); err != nil {
		return err
	}
	return announce(ctx, cfg, mac, mb, dev)
}

// pairingURLs returns the link the phone opens, and the mailbox address to
// put in the offer. The mailbox address is empty when the app is served by
// this computer itself; otherwise (the app comes from another of your
// machines) the offer says where this computer's mailbox is.
func pairingURLs(cfg config) (appURL, mailboxURL string, err error) {
	served, err := servedURL()
	if err != nil {
		return "", "", err
	}
	appURL = cfg.App
	if appURL == "" {
		appURL = served
	}
	if appURL != served {
		mailboxURL = served
	}
	return appURL, mailboxURL, nil
}

// showOffer prints the pairing QR code and link, and saves the code as a
// PNG too when png names a file.
func showOffer(link, png string, mac *identity.Mac) error {
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		return err
	}
	printQR(code)
	if png != "" {
		code.Scale = 12
		if err := os.WriteFile(png, code.PNG(), 0o600); err != nil {
			return err
		}
		fmt.Printf("QR code saved to %s\n", png)
	}
	fmt.Printf("\nScan with your phone's camera, or open:\n%s\n\n", link)
	fmt.Println("On an iPhone: the first time, this opens Safari. Add flow-remote to your Home Screen,")
	fmt.Println("open it from there, tap \"Scan the QR code\", and scan this code again.")
	fmt.Printf("This computer's fingerprint: %s\n", mac.Fingerprint())
	fmt.Printf("The code expires in %s. Waiting for the phone...\n", pairing.TTL)
	return nil
}

// waitForPhone polls the mailbox every two seconds until the phone answers
// the offer, the offer expires, or ctx ends.
func waitForPhone(ctx context.Context, mb *client.Client, offer pairing.Offer, mac *identity.Mac) (identity.Device, error) {
	for time.Now().UnixMilli() <= offer.Expires {
		e, err := mb.TakePair(ctx, offer.PairID)
		if err == nil {
			return pairing.Accept(offer, mac, e, time.Now())
		}
		if !errors.Is(err, client.ErrNotFound) {
			return identity.Device{}, err
		}
		select {
		case <-ctx.Done():
			return identity.Device{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return identity.Device{}, pairing.ErrExpired
}

// confirm prints question and reports whether the answer on stdin is "y".
func confirm(question string) bool {
	fmt.Print(question)
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.ToLower(strings.TrimSpace(ans)) == "y"
}

// announce hands a newly enrolled phone to the running server and tells
// the phone it's paired.
func announce(ctx context.Context, cfg config, mac *identity.Mac, mb *client.Client, dev identity.Device) error {
	if err := mb.PutDevice(ctx, dev); err != nil {
		return fmt.Errorf("enrolled here, but the running server didn't take it (it syncs on start): %w", err)
	}
	macName := cfg.Name
	if macName == "" {
		macName, _ = os.Hostname()
	}
	r := &relay.Relay{Mac: mac, Mailbox: mb}
	if err := r.SendTo(ctx, dev, protocol.Msg{Kind: protocol.KindPaired, MacName: macName}); err != nil {
		return fmt.Errorf("enrolled, but telling the phone failed: %w", err)
	}
	fmt.Printf("Enrolled %s. If the relay isn't running yet: `flow-remote start`.\n", dev.ID)
	return nil
}

// printQR draws the code with half blocks, two modules per character row,
// inside the quiet zone scanners need.
func printQR(c *qr.Code) {
	const quiet = 2
	at := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Black(x, y)
	}
	n := c.Size + 2*quiet
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		for x := 0; x < n; x++ {
			top, bot := at(x, y), at(x, y+1)
			// Light modules are drawn, dark are blank, so the code reads
			// correctly on a dark terminal.
			switch {
			case !top && !bot:
				b.WriteRune('█')
			case !top:
				b.WriteRune('▀')
			case !bot:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	fmt.Print(b.String())
}

func run(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	unlock, err := lockRun()
	if err != nil {
		return err
	}
	defer unlock()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ks := store()
	mac, err := identity.LoadOrCreateMac(ks)
	if err != nil {
		return err
	}
	devs, err := identity.LoadDevices(ks)
	if err != nil {
		return err
	}
	guard, err := envelope.LoadGuard(filepath.Join(home(), "seen.json"))
	if err != nil {
		return err
	}
	state, err := relay.LoadState(filepath.Join(home(), "forwarded.json"))
	if err != nil {
		return err
	}
	audit, err := os.OpenFile(filepath.Join(home(), "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer audit.Close()

	r := &relay.Relay{
		Mac: mac, Devices: devs, Guard: guard, State: state, Audit: audit, Log: log,
		Flow: flowcli.CLI{}, Update: availableUpdate,
	}
	if n := updateNotice(); n != "" {
		log.Info(n)
	}
	go checkForUpdates(ctx, log)
	return runLocal(ctx, cfg, r, log)
}

// runLocal serves phones from this machine: the app, the mailbox and the
// relay in this one process.
func runLocal(ctx context.Context, cfg config, r *relay.Relay, log *slog.Logger) error {
	var tun tunnel.Tunnel
	switch cfg.Tunnel {
	case "tailscale":
		tun = &tunnel.Tailscale{Dir: tailscaleDir(), Hostname: cfg.Hostname,
			Logf: func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }}
	case "none":
		tun = tunnel.Local{Addr: cfg.Listen, URL: cfg.PublicURL}
	default:
		return fmt.Errorf("config.json: tunnel %q: want tailscale or none", cfg.Tunnel)
	}
	origins := cfg.Origins
	if cfg.App != "" {
		origins = append(origins, cfg.App)
	}
	statePath := filepath.Join(home(), "serve.json")
	defer os.Remove(statePath)
	return serve.Run(ctx, serve.Options{
		Home: home(), Mac: r.Mac, Relay: r, Tunnel: tun, Origins: origins,
		DeviceIdle: 30 * 24 * time.Hour, Log: log,
		Listening: func(url string) {
			b, _ := json.Marshal(map[string]string{"url": url})
			if err := os.WriteFile(statePath, b, 0o600); err != nil {
				log.Warn("serve.json", "err", err)
			}
			log.Info("serving", "mac", r.Mac.ID, "devices", len(r.Devices.List()), "url", url)
		},
	})
}

// devices lists this Mac's active phones. Revoked ones stay on record, so
// their ids can never be enrolled again with a new key, and --all shows them.
func devices(args []string) error {
	all := len(args) > 0 && (args[0] == "--all" || args[0] == "-a")
	devs, err := identity.LoadDevices(store())
	if err != nil {
		return err
	}
	seen, idleDays := checkIns()
	shown, hidden := 0, 0
	for _, d := range devs.List() {
		if d.Revoked() && !all {
			hidden++
			continue
		}
		last, state := deviceState(d, seen, idleDays)
		fmt.Printf("%s  %-22q  %s  enrolled %s  %-22s %s\n", d.ID, d.Name, d.Fingerprint(), d.EnrolledAt.Format(time.DateOnly), last, state)
		shown++
	}
	if shown == 0 {
		fmt.Println("no phones enrolled; run `flow-remote pair`")
	}
	if hidden > 0 {
		fmt.Printf("(%d revoked, not shown: `flow-remote devices --all`)\n", hidden)
	}
	return nil
}

// checkIns asks the running server when each phone last checked in, and
// after how many idle days it stops taking a phone's messages. With the
// server stopped, it returns nothing, and the list says "unknown".
func checkIns() (map[string]client.DeviceStatus, int) {
	seen := map[string]client.DeviceStatus{}
	c, err := adminClient()
	if err != nil {
		return seen, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, idle, err := c.Devices(ctx)
	if err != nil {
		return seen, 0
	}
	for _, d := range list {
		seen[d.ID] = d
	}
	return seen, idle
}

// deviceState describes when a phone was last seen, and whether it's
// active, expired or revoked.
func deviceState(d identity.Device, seen map[string]client.DeviceStatus, idleDays int) (last, state string) {
	if d.Revoked() {
		return "", "revoked " + d.RevokedAt.Format(time.DateOnly)
	}
	st, ok := seen[d.ID]
	if !ok {
		return "last seen unknown", "active"
	}
	last, state = "never seen", "active"
	if st.LastSeen != nil {
		last = "last seen " + ago(*st.LastSeen)
	}
	if st.Expired {
		state = "expired (unused " + fmt.Sprint(idleDays) + "+ days; pair again)"
	}
	return last, state
}

// ago says how long ago t was, to the second, with the clock time, so
// "last seen" isn't rounded down to a whole minute or hour.
func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		d = 0 // a clock slightly ahead of ours
	}
	var rel string
	switch {
	case d < 2*time.Second:
		rel = "just now"
	case d < time.Minute:
		rel = fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		rel = fmt.Sprintf("%dm %ds ago", int(d.Minutes()), int(d.Seconds())%60)
	case d < 48*time.Hour:
		rel = fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	default:
		rel = fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	format := "15:04:05"
	if d >= 24*time.Hour {
		format = "Jan 2 15:04"
	}
	return rel + " (" + t.Local().Format(format) + ")"
}

func revoke(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: flow-remote revoke <device-id>")
	}
	ks := store()
	devs, err := identity.LoadDevices(ks)
	if err != nil {
		return err
	}
	if _, known := devs.Active(args[0]); !known && !slices.ContainsFunc(devs.List(), func(d identity.Device) bool { return d.ID == args[0] }) {
		// Not in this Mac's list, e.g. lost from a damaged registry. The
		// server may still accept it, so revoke it there anyway.
		fmt.Printf("%s isn't in this computer's device list; revoking it on the server only.\n", args[0])
	} else {
		if err := devs.Revoke(args[0], time.Now()); err != nil {
			return err
		}
		fmt.Printf("revoked %s. The relay rejects everything it signs from now on.\n", args[0])
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	mac, err := identity.LoadOrCreateMac(ks)
	if err != nil {
		return err
	}
	mb := mailboxClient(cfg, mac)
	if err := mb.RevokeDevice(context.Background(), args[0]); errors.Is(err, client.ErrNotFound) {
		fmt.Println("the server doesn't have it either; nothing more to do.")
		return nil
	} else if err != nil {
		fmt.Printf("the running server didn't get the revocation (%v); it picks it up when it next starts.\n", explain(err))
		return nil
	}
	fmt.Println("the running server rejects its requests too.")
	return nil
}

func adminClient() (*client.Client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	mac, err := identity.LoadOrCreateMac(store())
	if err != nil {
		return nil, err
	}
	return mailboxClient(cfg, mac), nil
}
