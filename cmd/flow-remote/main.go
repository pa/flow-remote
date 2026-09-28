// Command flow-remote is the Mac side of flow-remote: it sets up this Mac,
// pairs phones, and runs the relay that carries messages between the
// mailbox and flow sessions.
//
//	flow-remote setup --mailbox URL [--app URL]
//	                                      save where the mailbox lives and
//	                                      register this Mac: the first Mac with
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
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"rsc.io/qr"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/flowcli"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/keystore"
	"github.com/pa/flow-remote/internal/pairing"
	"github.com/pa/flow-remote/internal/protocol"
	"github.com/pa/flow-remote/internal/relay"
)

// version is set at release build time (-ldflags "-X main.version=v1.2.3").
var version = "dev"

type config struct {
	Mailbox string `json:"mailbox"`
	App     string `json:"app"`
	Name    string `json:"name,omitempty"` // what phones call this Mac
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
  setup --mailbox URL [--name N]    set up this Mac (FLOW_REMOTE_SETUP_TOKEN or FLOW_REMOTE_INVITE)
  pair [--png FILE]                 show a QR code and enroll a phone
  start | stop | status             run the relay in the background (launchd)
  run                               run the relay in the foreground
  devices [--all] | revoke <id>     list this Mac's phones (--all: with revoked), or revoke one
  invite                            (admin) a single-use code for another Mac
  tenants | remove-tenant <mac-id>  (admin) list or remove Macs
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
		return c, errors.New("run `flow-remote setup --mailbox URL` first")
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}

func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	mb := fs.String("mailbox", "", "mailbox base URL")
	app := fs.String("app", "", "phone app URL (default: the mailbox URL)")
	name := fs.String("name", "", "what phones call this Mac (default: its hostname)")
	fs.Parse(args)
	if *mb == "" {
		return errors.New("--mailbox is required")
	}
	if *app == "" {
		*app = *mb // the mailbox serves the phone app too
	}
	b, _ := json.MarshalIndent(config{Mailbox: strings.TrimRight(*mb, "/"), App: strings.TrimRight(*app, "/"), Name: *name}, "", "  ")
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(home(), "config.json"), b, 0o600); err != nil {
		return err
	}
	mac, err := identity.LoadOrCreateMac(store())
	if err != nil {
		return err
	}
	fmt.Printf("saved. This Mac is %s, fingerprint %s\n", mac.ID, mac.Fingerprint())
	// The token comes from the environment so it stays out of shell
	// history and the process list.
	// Secrets come from the environment so they stay out of shell history
	// and the process list.
	tok, inv := os.Getenv("FLOW_REMOTE_SETUP_TOKEN"), os.Getenv("FLOW_REMOTE_INVITE")
	c := &client.Client{BaseURL: strings.TrimRight(*mb, "/"), Mac: mac}
	if err := c.Register(context.Background(), tok, inv); err != nil {
		if tok == "" && inv == "" {
			fmt.Println("not registered yet. Ask an admin Mac for `flow-remote invite`, then run setup again with FLOW_REMOTE_INVITE=<code>.")
			return nil
		}
		return fmt.Errorf("registering with the mailbox: %w", err)
	}
	fmt.Println("registered with the mailbox. Next: `flow-remote start`, then `flow-remote pair`.")
	return nil
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
	mb := &client.Client{BaseURL: cfg.Mailbox, Mac: mac}

	offer := pairing.NewOffer(mac, "", time.Now()) // the phone uses its own origin
	if err := mb.OpenPair(ctx, offer.PairID); err != nil {
		return fmt.Errorf("opening the pairing at the mailbox: %w", err)
	}
	link := offer.Link(cfg.App)
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
	fmt.Printf("This Mac's fingerprint: %s\n", mac.Fingerprint())
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

// maxBackoff caps the wait between retries while the mailbox is
// unreachable (Wi-Fi down, Mac asleep), so the relay is back within this
// long of the network returning.
const maxBackoff = 30 * time.Second

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
		Mailbox: &client.Client{BaseURL: cfg.Mailbox, Mac: mac},
		Flow:    flowcli.CLI{},
	}
	syncDevices(ctx, r.Mailbox.(*client.Client), devs, log)
	log.Info("relay running", "mac", mac.ID, "devices", len(devs.List()), "mailbox", cfg.Mailbox)
	backoff := time.Second
	for {
		wait, err := r.Tick(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Warn("tick", "err", err)
			wait, backoff = backoff, min(backoff*2, maxBackoff)
		} else {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
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

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 5*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
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
	if err := devs.Revoke(args[0], time.Now()); err != nil {
		return err
	}
	fmt.Printf("revoked %s. The relay rejects everything it signs from now on.\n", args[0])
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	mac, err := identity.LoadOrCreateMac(ks)
	if err != nil {
		return err
	}
	mb := &client.Client{BaseURL: cfg.Mailbox, Mac: mac}
	if err := mb.RevokeDevice(context.Background(), args[0]); err != nil {
		fmt.Printf("the mailbox didn't get the revocation (%v); the relay retries it when it next starts.\n", err)
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
	return &client.Client{BaseURL: cfg.Mailbox, Mac: mac}, nil
}

func invite(ctx context.Context) error {
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

On the other Mac, after installing flow-remote:

  FLOW_REMOTE_INVITE=%s flow-remote setup --mailbox %s

The invite adds that Mac as its own tenant. It can't see or reach this
Mac's sessions or phones, and this Mac can't reach its. Both of you still
trust whoever runs this mailbox: it serves the phone app's code.
`, exp.Local().Format(time.RFC1123), code, code, c.BaseURL)
	return nil
}

func tenants(ctx context.Context) error {
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
			me = "  (this Mac)"
		}
		fmt.Printf("%s  %-6s  joined %s  last seen %s%s\n", t.ID, role, t.Created.Local().Format(time.DateOnly), seen, me)
	}
	return nil
}

func removeTenant(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: flow-remote remove-tenant <mac-id>")
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
