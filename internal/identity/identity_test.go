package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/pa/flow-remote/internal/keystore"
)

func TestMacPersists(t *testing.T) {
	ks := keystore.Dir{Path: t.TempDir()}
	a, err := LoadOrCreateMac(ks)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateMac(ks)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID || a.SignPub() != b.SignPub() || a.BoxPub() != b.BoxPub() {
		t.Fatal("identity changed across loads")
	}
	if !strings.HasPrefix(a.ID, "mac-") {
		t.Fatalf("id %q", a.ID)
	}
	if fp := a.Fingerprint(); len(fp) != 24 || strings.Count(fp, " ") != 4 {
		t.Fatalf("fingerprint %q", fp)
	}
}

func TestDevices(t *testing.T) {
	ks := &keystore.Memory{}
	d, _ := LoadDevices(ks)
	now := time.Now()
	dev := Device{ID: "dev-aaaaaaaa", Name: "phone", SignPub: "s", BoxPub: "b", EnrolledAt: now}
	if err := d.Enroll(dev); err != nil {
		t.Fatal(err)
	}
	if err := d.Enroll(dev); err == nil {
		t.Fatal("double enroll allowed")
	}

	d2, _ := LoadDevices(ks)
	if _, ok := d2.Active(dev.ID); !ok {
		t.Fatal("device lost on reload")
	}
	if err := d2.Revoke(dev.ID, now); err != nil {
		t.Fatal(err)
	}
	d3, _ := LoadDevices(ks)
	if _, ok := d3.Active(dev.ID); ok {
		t.Fatal("revoked device still active")
	}
	if err := d3.Enroll(dev); err == nil {
		t.Fatal("revoked id re-enrolled")
	}
}
