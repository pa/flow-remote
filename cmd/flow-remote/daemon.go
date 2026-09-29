package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"
)

// agentLabel names the launchd agent for this home. The default home
// gets the plain label; any other (FLOW_REMOTE_HOME) gets its own, so
// starting a test setup can't replace the real relay's agent.
func agentLabel() string {
	const base = "com.github.pa.flow-remote.relay"
	h, _ := os.UserHomeDir()
	if filepath.Clean(home()) == filepath.Join(h, ".flow-remote") {
		return base
	}
	sum := sha256.Sum256([]byte(filepath.Clean(home())))
	return base + "." + hex.EncodeToString(sum[:4])
}

func agentPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents", agentLabel()+".plist")
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

var plistTmpl = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{{.Label}}</string>
  <key>ProgramArguments</key>
  <array><string>{{.Bin}}</string><string>run</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>{{.Path}}</string>
    <key>FLOW_REMOTE_HOME</key><string>{{.Home}}</string>{{if .Keystore}}
    <key>FLOW_REMOTE_KEYSTORE</key><string>{{.Keystore}}</string>{{end}}
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardErrorPath</key><string>{{.Log}}</string>
  <key>StandardOutPath</key><string>{{.Log}}</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
`))

// agentStart installs the launchd agent and starts it. The relay then runs at
// every login and is restarted if it crashes.
func agentStart() error {
	if _, err := loadConfig(); err != nil {
		return err
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if bin, err = filepath.EvalSymlinks(bin); err != nil {
		return err
	}
	if strings.Contains(bin, "/go-build") {
		return errors.New("run `flow-remote start` from an installed binary (go install ./cmd/flow-remote), not `go run`")
	}
	var buf bytes.Buffer
	if err := plistTmpl.Execute(&buf, map[string]string{
		"Label": agentLabel(), "Bin": bin, "Home": home(),
		// launchd starts with a bare PATH; keep this shell's so `flow` is found.
		"Path": os.Getenv("PATH"),
		"Log":  filepath.Join(home(), "relay.log"),
		// A test setup's keys, so its agent doesn't use the Keychain's.
		"Keystore": os.Getenv("FLOW_REMOTE_KEYSTORE"),
	}); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(agentPath()), 0o755); err != nil {
		return err
	}
	// Replace a loaded agent so a new binary or PATH takes effect. bootout
	// returns before the old one has finished unloading, and bootstrapping
	// over it fails with "Input/output error", so wait for it to go.
	exec.Command("launchctl", "bootout", domain()+"/"+agentLabel()).Run()
	for i := 0; i < 50 && exec.Command("launchctl", "print", domain()+"/"+agentLabel()).Run() == nil; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.WriteFile(agentPath(), buf.Bytes(), 0o644); err != nil {
		return err
	}
	var out []byte
	for attempt := 0; attempt < 3; attempt++ {
		if out, err = exec.Command("launchctl", "bootstrap", domain(), agentPath()).CombinedOutput(); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("relay started. It runs at login and restarts if it crashes.\n  agent: %s\n  log:   %s\n", agentPath(), filepath.Join(home(), "relay.log"))
	return nil
}

// agentStop unloads the agent and removes it, so it doesn't come back at login.
func agentStop() error {
	out, err := exec.Command("launchctl", "bootout", domain()+"/"+agentLabel()).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such process") && !strings.Contains(string(out), "Could not find") {
		return fmt.Errorf("launchctl bootout: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := os.Remove(agentPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("relay stopped and removed from login items. `flow-remote start` brings it back.")
	return nil
}

func agentStatus() error {
	out, err := exec.Command("launchctl", "print", domain()+"/"+agentLabel()).CombinedOutput()
	if err != nil {
		fmt.Println("relay agent: not installed (`flow-remote start` installs it)")
	} else {
		state, pid := "unknown", "-"
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "state = "); ok {
				state = v
			}
			if v, ok := strings.CutPrefix(line, "pid = "); ok {
				pid = v
			}
		}
		fmt.Printf("relay agent: %s (pid %s)\n", state, pid)
	}
	if cfg, err := loadConfig(); err == nil {
		url, err := servedURL()
		if err != nil {
			url = "(not serving)"
		}
		fmt.Printf("serving:     %s (tunnel %s)\n", url, cfg.Tunnel)
	}
	log := filepath.Join(home(), "relay.log")
	if b, err := os.ReadFile(log); err == nil {
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) > 5 {
			lines = lines[len(lines)-5:]
		}
		fmt.Printf("last log lines (%s):\n  %s\n", log, strings.Join(lines, "\n  "))
	}
	return nil
}

// lockRun makes sure only one relay runs at a time. Two would both deliver
// every message and race on the replay list.
func lockRun() (release func(), err error) {
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(home(), "relay.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another relay is already running (check `flow-remote status`, or stop the other one first)")
	}
	f.Truncate(0)
	fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() { f.Close() }, nil
}
