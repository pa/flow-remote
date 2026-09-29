package tunnel

import (
	"context"
	"strings"
	"testing"
)

func TestHostname(t *testing.T) {
	for in, want := range map[string]string{
		"My Mac":                "flow-remote-my-mac",
		"Sam’S MacBook Pro (2)": "flow-remote-sam-s-macbook-pro-2",
		"":                      "flow-remote",
		"---":                   "flow-remote",
		strings.Repeat("a", 80): "flow-remote-" + strings.Repeat("a", 51),
	} {
		if got := Hostname(in); got != want {
			t.Errorf("Hostname(%q) = %q, want %q", in, got, want)
		}
	}
}

// Without a joined device or a key, Listen fails at once instead of
// waiting for a login.
func TestNotJoined(t *testing.T) {
	ts := &Tailscale{Dir: t.TempDir(), Hostname: "flow-remote-test"}
	if _, _, err := ts.Listen(context.Background()); err == nil || !strings.Contains(err.Error(), "setup --tunnel tailscale") {
		t.Fatalf("Listen = %v", err)
	}
}

func TestLocal(t *testing.T) {
	ln, url, err := Local{Addr: "127.0.0.1:0"}.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if url != "http://"+ln.Addr().String() {
		t.Fatalf("url = %q", url)
	}
}
