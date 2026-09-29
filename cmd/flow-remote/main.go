// Command flow-remote is the Mac side of flow-remote: it sets up this Mac,
// pairs phones, and runs the relay that carries messages between phones
// and flow sessions.
//
// Two ways to run. With a tunnel, this process is the server: it serves
// the phone app and the mailbox itself, and phones reach it through the
// tunnel. With a hosted mailbox, the relay polls one running elsewhere.
//
//	flow-remote setup --tunnel tailscale [--name N]
//	                                      serve from this machine over your
//	                                      tailnet; asks for a single-use auth
//	                                      key tagged tag:flow-remote
//	flow-remote setup --tunnel none --listen ADDR --public-url URL
//	                                      serve from this machine; you route
//	                                      URL to ADDR (TLS must end here)
//	flow-remote setup --mailbox URL [--app URL]
//	                                      use a hosted mailbox and register
//	                                      this Mac: the first Mac with
//	                                      FLOW_REMOTE_SETUP_TOKEN, others with
//	                                      FLOW_REMOTE_INVITE from `invite`
//	flow-remote pair [--png FILE]               show a QR code (and optionally save it
//	                                      as an image) and enroll a phone
//	flow-remote run                             deliver messages in the foreground
//	flow-remote start | stop | status           run it as a launchd agent (at login,
//	                                      restarted on crash), stop it, check it
//	flow-remote devices                         list enrolled phones
//	flow-remote revoke <device-id>              stop trusting a phone
//	flow-remote invite                          (admin) a single-use code for another Mac
//	flow-remote tenants                         (admin) list the Macs using this mailbox
//	flow-remote remove-tenant <mac-id>          (admin) remove a Mac, its phones and mail
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
	// Tunnel set means this machine serves phones itself. Empty means a
	// hosted mailbox at Mailbox.
	Tunnel    string   `json:"tunnel,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`   // tunnel "tailscale": the tailnet device name
	Listen    string   `json:"listen,omitempty"`     // tunnel "none": where to listen
	PublicURL string   `json:"public_url,omitempty"` // tunnel "none": what phones use
	Origins   []string `json:"origins,omitempty"`    // other app addresses allowed to call this one
	Mailbox   string   `json:"mailbox,omitempty"`
	App       string   `json:"app,omitempty"`
	Name      string   `json:"name,omitempty"` // what phones call this Mac
}

func (c config) local() bool { return c.Tunnel != "" }

// mailboxClient reaches this Mac's mailbox: the socket of the running
// serve, or the hosted one.
func mailboxClient(c config, mac *identity.Mac) *client.Client {
	if c.local() {
		return serve.Client(home(), mac)
	}
	return &client.Client{BaseURL: c.Mailbox, Mac: mac}
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
	case "devices":
		err = devices(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	case "invite":
		err = invite(ctx)
	case "tenants":
		err = tenants(ctx)
	case "remove-tenant":
		err = removeTenant(ctx, os.Args[2:])
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
  setup --tunnel tailscale [--name N]
                                    serve this computer's phones over your tailnet (asks for an auth key)
  setup --mailbox URL [--name N]    set up this computer with a hosted mailbox (FLOW_REMOTE_SETUP_TOKEN or FLOW_REMOTE_INVITE)
  pair [--png FILE]                 show a QR code and enroll a phone
  start | stop | status             run the relay in the background (launchd)
  run                               run the relay in the foreground
  devices [--all] | revoke <id>     list this computer's phones (--all: with revoked), or revoke one
  invite                            (admin) a single-use code for another computer
  tenants | remove-tenant <mac-id>  (admin) list or remove computers
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
	return c, json.Unmarshal(b, &c)
}

func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	tun := fs.String("tunnel", "", "serve phones from this machine through this tunnel: tailscale or none")
	listen := fs.String("listen", "127.0.0.1:8484", "tunnel none: address to listen on")
	public := fs.String("public-url", "", "tunnel none: the https URL phones use to reach --listen")
	mb := fs.String("mailbox", "", "hosted mailbox base URL")
	app := fs.String("app", "", "phone app URL (default: this machine's, or the mailbox's)")
	name := fs.String("name", "", "what phones call this computer (default: its hostname)")
	fs.Parse(args)
	if *tun != "" {
		return setupLocal(*tun, *listen, *public, *app, *name)
	}
	if *mb == "" {
		return errors.New("--tunnel or --mailbox is required")
	}
	if *app == "" {
		*app = *mb // the mailbox serves the phone app too
	}
	if err := writeConfig(config{Mailbox: strings.TrimRight(*mb, "/"), App: strings.TrimRight(*app, "/"), Name: *name}); err != nil {
		return err
	}
	mac, err := identity.LoadOrCreateMac(store())
	if err != nil {
		return err
	}
	fmt.Printf("saved. This computer is %s, fingerprint %s\n", mac.ID, mac.Fingerprint())
	// Secrets come from the environment so they stay out of shell history
	// and the process list.
	tok, inv := os.Getenv("FLOW_REMOTE_SETUP_TOKEN"), os.Getenv("FLOW_REMOTE_INVITE")
	c := &client.Client{BaseURL: strings.TrimRight(*mb, "/"), Mac: mac}
	if err := c.Register(context.Background(), tok, inv); err != nil {
		if tok == "" && inv == "" {
			fmt.Println("not registered yet. Ask an admin computer for `flow-remote invite`, then run setup again with FLOW_REMOTE_INVITE=<code>.")
			return nil
		}
		return fmt.Errorf("registering with the mailbox: %w", err)
	}
	fmt.Println("registered with the mailbox. Next: `flow-remote start`, then `flow-remote pair`.")
	return nil
}

// setupLocal saves the settings for serving from this machine. Nothing to
// register: `run` makes this Mac the only tenant of its own mailbox.
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
	if name == "" {
		name, _ = os.Hostname()
		name = strings.TrimSuffix(name, ".local")
	}
	host := tunnel.Hostname(name)
	if prev, err := loadConfig(); err == nil && prev.Tunnel == "tailscale" && prev.Hostname != "" {
		// Keep the name: it's part of the app's address, and a new one means
		// pairing every phone again.
		host = prev.Hostname
	}
	ts := &tunnel.Tailscale{Dir: tailscaleDir(), Hostname: host, Logf: func(f string, a ...any) { fmt.Printf(f+"\n", a...) }}
	if !tunnel.Joined(ts.Dir) {
		key := os.Getenv("TS_AUTHKEY")
		if key == "" {
			fmt.Println("Tailscale auth key: in the admin console, Settings > Keys > Generate auth key,")
			fmt.Println("single-use, not ephemeral, pre-approved, tagged tag:flow-remote.")
			fmt.Print("Paste it (input hidden): ")
			var b []byte
			var err error
			if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
				b, err = term.ReadPassword(fd)
			} else { // piped in, e.g. from a password manager's CLI
				b, err = bufio.NewReader(os.Stdin).ReadBytes('\n')
				if errors.Is(err, io.EOF) {
					err = nil
				}
			}
			fmt.Println()
			if err != nil {
				return fmt.Errorf("reading the key: %w", err)
			}
			key = strings.TrimSpace(string(b))
		}
		if !strings.HasPrefix(key, "tskey-") {
			return errors.New("that doesn't look like a Tailscale auth key (tskey-...)")
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

	// The app opens the pairing link. When it's served from somewhere other
	// than this Mac's mailbox (another of your machines), the offer says
	// where the mailbox is.
	appURL, mailboxURL := cfg.App, ""
	if cfg.local() {
		served, err := servedURL()
		if err != nil {
			return err
		}
		if appURL == "" {
			appURL = served
		}
		if appURL != served {
			mailboxURL = served
		}
	}
	offer := pairing.NewOffer(mac, mailboxURL, time.Now())
	if err := mb.OpenPair(ctx, offer.PairID); err != nil {
		return fmt.Errorf("opening the pairing at the mailbox: %w", explain(err))
	}
	link := offer.Link(appURL)
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		return err
	}
	printQR(code)
	if *png != "" {
		code.Scale = 12
		if err := os.WriteFile(*png, code.PNG(), 0o600); err != nil {
			return err
		}
		fmt.Printf("QR code saved to %s\n", *png)
	}
	fmt.Printf("\nScan with your phone's camera, or open:\n%s\n\n", link)
	fmt.Println("On an iPhone: the first time, this opens Safari. Add flow-remote to your Home Screen,")
	fmt.Println("open it from there, tap \"Scan the QR code\", and scan this code again.")
	fmt.Printf("This computer's fingerprint: %s\n", mac.Fingerprint())
	fmt.Printf("The code expires in %s. Waiting for the phone...\n", pairing.TTL)

	var dev identity.Device
	for {
		if time.Now().UnixMilli() > offer.Expires {
			return pairing.ErrExpired
		}
		e, err := mb.TakePair(ctx, offer.PairID)
		if errors.Is(err, client.ErrNotFound) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}
		if err != nil {
			return err
		}
		if dev, err = pairing.Accept(offer, mac, e, time.Now()); err != nil {
			return err
		}
		break
	}

	fmt.Printf("\nPhone: %q\nIts fingerprint: %s\n", dev.Name, dev.Fingerprint())
	fmt.Print("Does that match the fingerprint on the phone's screen? Enroll it? [y/N] ")
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.ToLower(strings.TrimSpace(ans)) != "y" {
		return errors.New("not enrolled")
	}
	if err := devs.Enroll(dev); err != nil {
		return err
	}
	if err := mb.PutDevice(ctx, dev); err != nil {
		return fmt.Errorf("enrolled here, but registering it with the mailbox failed (the relay retries on start): %w", err)
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
	allow, err := relay.LoadAllowlist(filepath.Join(home(), "allow.txt"))
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
		Mac: mac, Devices: devs, Guard: guard, Allow: allow, State: state, Audit: audit, Log: log,
		Flow: flowcli.CLI{},
	}
	if cfg.local() {
		return runLocal(ctx, cfg, r, log)
	}
	mb := &client.Client{BaseURL: cfg.Mailbox, Mac: mac}
	r.Mailbox = mb
	syncDevices(ctx, mb, devs, log)
	log.Info("relay running", "mac", mac.ID, "devices", len(devs.List()), "mailbox", cfg.Mailbox)
	return r.Loop(ctx, nil)
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

// syncDevices makes the mailbox's device list match the Keychain's, in
// case a registration or revocation failed earlier.
func syncDevices(ctx context.Context, mb *client.Client, devs *identity.Devices, log *slog.Logger) {
	for _, d := range devs.List() {
		var err error
		if d.Revoked() {
			err = mb.RevokeDevice(ctx, d.ID)
		} else {
			err = mb.PutDevice(ctx, d)
		}
		if err != nil {
			log.Warn("device sync", "device", d.ID, "err", err)
		}
	}
}

// devices lists this Mac's active phones. Revoked ones stay on record, so
// their ids can never be enrolled again with a new key, and --all shows them.
func devices(args []string) error {
	all := len(args) > 0 && (args[0] == "--all" || args[0] == "-a")
	devs, err := identity.LoadDevices(store())
	if err != nil {
		return err
	}
	// Ask the mailbox when each phone last checked in; offline is fine.
	seen := map[string]client.DeviceStatus{}
	idleDays := 0
	if c, err := adminClient(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if list, idle, err := c.Devices(ctx); err == nil {
			idleDays = idle
			for _, d := range list {
				seen[d.ID] = d
			}
		}
		cancel()
	}
	shown, hidden := 0, 0
	for _, d := range devs.List() {
		if d.Revoked() && !all {
			hidden++
			continue
		}
		state, last := "active", "last seen unknown"
		if st, ok := seen[d.ID]; ok {
			if st.LastSeen != nil {
				last = "last seen " + ago(*st.LastSeen)
			} else {
				last = "never seen"
			}
			if st.Expired {
				state = "expired (unused " + fmt.Sprint(idleDays) + "+ days; pair again)"
			}
		}
		if d.Revoked() {
			state, last = "revoked "+d.RevokedAt.Format(time.DateOnly), ""
		}
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

// ago says how long ago t was, to the second, with the clock time, so
// "last seen" isn't rounded down to a whole minute or hour.
func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		d = 0 // the mailbox's clock is slightly ahead of ours
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
		// mailbox may still accept it, so revoke it there anyway.
		fmt.Printf("%s isn't in this computer's device list; revoking it on the mailbox only.\n", args[0])
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
		fmt.Println("the mailbox doesn't have it either; nothing more to do.")
		return nil
	} else if err != nil {
		fmt.Printf("the mailbox didn't get the revocation (%v); the relay retries it when it next starts.\n", explain(err))
		return nil
	}
	fmt.Println("the mailbox rejects its requests too.")
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

// hostedOnly refuses the tenant commands when this machine serves itself:
// its mailbox has one tenant, this Mac.
func hostedOnly() error {
	if cfg, err := loadConfig(); err == nil && cfg.local() {
		return errors.New("this computer serves its own phones, so there are no other tenants to manage")
	}
	return nil
}

func invite(ctx context.Context) error {
	if err := hostedOnly(); err != nil {
		return err
	}
	c, err := adminClient()
	if err != nil {
		return err
	}
	code, exp, err := c.Invite(ctx)
	if err != nil {
		return err
	}
	fmt.Printf(`Single-use invite, valid until %s:

  %s

On the other computer, after installing flow-remote:

  FLOW_REMOTE_INVITE=%s flow-remote setup --mailbox %s

The invite adds that computer as its own tenant. It can't see or reach this
computer's sessions or phones, and this computer can't reach its. Both of you still
trust whoever runs this mailbox: it serves the phone app's code.
`, exp.Local().Format(time.RFC1123), code, code, c.BaseURL)
	return nil
}

func tenants(ctx context.Context) error {
	if err := hostedOnly(); err != nil {
		return err
	}
	c, err := adminClient()
	if err != nil {
		return err
	}
	list, err := c.Tenants(ctx)
	if err != nil {
		return err
	}
	for _, t := range list {
		role, seen := "member", "never"
		if t.Admin {
			role = "admin"
		}
		if t.LastSeen != nil {
			seen = t.LastSeen.Local().Format(time.DateTime)
		}
		me := ""
		if t.ID == c.Mac.ID {
			me = "  (this computer)"
		}
		fmt.Printf("%s  %-6s  joined %s  last seen %s%s\n", t.ID, role, t.Created.Local().Format(time.DateOnly), seen, me)
	}
	return nil
}

func removeTenant(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: flow-remote remove-tenant <mac-id>")
	}
	if err := hostedOnly(); err != nil {
		return err
	}
	c, err := adminClient()
	if err != nil {
		return err
	}
	if err := c.RemoveTenant(ctx, args[0]); err != nil {
		return err
	}
	fmt.Printf("removed %s, its phones and its queued mail.\n", args[0])
	return nil
}
