// Command relay is the Mac side of flow-remote.
//
//	relay setup --mailbox URL --app URL   save where the mailbox and app live
//	relay pair                            show a QR code and enroll a phone
//	relay run                             deliver messages (launchd runs this)
//	relay devices                         list enrolled phones
//	relay revoke <device-id>              stop trusting a phone
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

type config struct {
	Mailbox string `json:"mailbox"`
	App     string `json:"app"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "setup":
		err = setup(os.Args[2:])
	case "pair":
		err = pair(ctx)
	case "run":
		err = run(ctx)
	case "devices":
		err = devices()
	case "revoke":
		err = revoke(os.Args[2:])
	default:
		usage()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relay setup --mailbox URL --app URL | pair | run | devices | revoke <device-id>")
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
		return c, errors.New("run `relay setup --mailbox URL --app URL` first")
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}

func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	mb := fs.String("mailbox", "", "mailbox base URL")
	app := fs.String("app", "", "phone app URL")
	fs.Parse(args)
	if *mb == "" || *app == "" {
		return errors.New("both --mailbox and --app are required")
	}
	b, _ := json.MarshalIndent(config{Mailbox: strings.TrimRight(*mb, "/"), App: strings.TrimRight(*app, "/")}, "", "  ")
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
	return nil
}

func pair(ctx context.Context) error {
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
	link := offer.Link(cfg.App)
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		return err
	}
	printQR(code)
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
	host, _ := os.Hostname()
	r := &relay.Relay{Mac: mac, Mailbox: mb}
	if err := r.SendTo(ctx, dev, protocol.Msg{Kind: protocol.KindPaired, MacName: host}); err != nil {
		return fmt.Errorf("enrolled, but telling the phone failed: %w", err)
	}
	fmt.Printf("Enrolled %s. Start the relay with `relay run` (or the launchd agent).\n", dev.ID)
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
	log.Info("relay running", "mac", mac.ID, "devices", len(devs.List()), "mailbox", cfg.Mailbox)
	backoff := time.Second
	for {
		wait, err := r.Tick(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Warn("tick", "err", err)
			wait, backoff = backoff, min(backoff*2, 5*time.Minute)
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

func devices() error {
	devs, err := identity.LoadDevices(store())
	if err != nil {
		return err
	}
	list := devs.List()
	if len(list) == 0 {
		fmt.Println("no phones enrolled; run `relay pair`")
	}
	for _, d := range list {
		state := "active"
		if d.Revoked() {
			state = "revoked " + d.RevokedAt.Format(time.DateOnly)
		}
		fmt.Printf("%s  %-24q  %s  enrolled %s  %s\n", d.ID, d.Name, d.Fingerprint(), d.EnrolledAt.Format(time.DateOnly), state)
	}
	return nil
}

func revoke(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: relay revoke <device-id>")
	}
	devs, err := identity.LoadDevices(store())
	if err != nil {
		return err
	}
	if err := devs.Revoke(args[0], time.Now()); err != nil {
		return err
	}
	fmt.Printf("revoked %s. The relay rejects everything it signs from now on.\n", args[0])
	return nil
}
