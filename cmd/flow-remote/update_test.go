package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"v0.1.2", "v0.1.1", true},
		{"v0.2.0", "v0.1.9", true},
		{"v0.10.0", "v0.9.0", true},
		{"v0.1.1", "v0.1.1", false},
		{"v0.1.0", "v0.1.1", false},
		{"v0.1.2", "dev", false},
		{"garbage", "v0.1.1", false},
	} {
		if got := newer(tc.a, tc.b); got != tc.want {
			t.Errorf("newer(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestUpdateNotice(t *testing.T) {
	t.Setenv("FLOW_REMOTE_HOME", t.TempDir())
	old := version
	version = "v0.1.1"
	defer func() { version = old }()
	if n := updateNotice(); n != "" {
		t.Fatalf("no check yet, but notice %q", n)
	}
	write := func(tag string) {
		os.WriteFile(filepath.Join(home(), "latest.json"), []byte(`{"tag":"`+tag+`"}`), 0o600)
	}
	write("v0.1.1")
	if n := updateNotice(); n != "" {
		t.Fatalf("up to date, but notice %q", n)
	}
	write("v0.1.2")
	if n := updateNotice(); n != "flow-remote v0.1.2 is out (this is v0.1.1). Run `flow-remote upgrade`." {
		t.Fatalf("notice %q", n)
	}
}
