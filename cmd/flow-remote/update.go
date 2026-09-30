package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// How often a running flow-remote asks GitHub for the latest release.
// FLOW_REMOTE_NO_UPDATE_CHECK=1 turns the check off.
const updateEvery = 24 * time.Hour

// latestSeen is what the last update check found, in ~/.flow-remote/latest.json.
type latestSeen struct {
	Tag     string    `json:"tag"`
	Checked time.Time `json:"checked"`
}

func latestPath() string { return filepath.Join(home(), "latest.json") }

// availableUpdate returns the release the last check found if it's newer
// than this build, or "".
func availableUpdate() string {
	b, err := os.ReadFile(latestPath())
	if err != nil {
		return ""
	}
	var l latestSeen
	if json.Unmarshal(b, &l) != nil || !newer(l.Tag, version) {
		return ""
	}
	return l.Tag
}

// updateNotice is the line that tells you to upgrade, or "".
func updateNotice() string {
	u := availableUpdate()
	if u == "" {
		return ""
	}
	return fmt.Sprintf("flow-remote %s is out (this is %s). Run `flow-remote upgrade`.", u, version)
}

// checkForUpdates looks up the latest release a minute after starting and
// then once a day, until ctx ends. The lookup is anonymous, like upgrade.
func checkForUpdates(ctx context.Context, log *slog.Logger) {
	if os.Getenv("FLOW_REMOTE_NO_UPDATE_CHECK") == "1" {
		return
	}
	wait := time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = updateEvery
		if err := checkOnce(ctx); err != nil {
			log.Warn("update check", "err", err)
		} else if n := updateNotice(); n != "" {
			log.Info(n)
		}
	}
}

// checkOnce records the latest release's tag in latest.json.
func checkOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	rel, err := latestRelease(ctx)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(latestSeen{Tag: rel.Tag, Checked: time.Now().UTC()})
	return os.WriteFile(latestPath(), b, 0o600)
}

// newer reports whether version a is later than b. Both look like v1.2.3;
// anything else, such as a "dev" build, is never newer or older.
func newer(a, b string) bool {
	va, ok1 := parseVersion(a)
	vb, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 || !strings.HasPrefix(v, "v") {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
