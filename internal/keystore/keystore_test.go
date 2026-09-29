package keystore

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"
)

func exercise(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.Get("item-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing get = %v", err)
	}
	val := []byte{0, 1, 2, 255, ' ', '"', '\n'}
	if err := s.Put("item-a", val); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("item-a", append(val, 9)); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := s.Get("item-a")
	if err != nil || !bytes.Equal(got, append(val, 9)) {
		t.Fatalf("get = %v, %v", got, err)
	}
	if err := s.Delete("item-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("item-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
	if err := s.Put("bad name; rm", nil); err == nil {
		t.Fatal("bad name accepted")
	}
}

func TestMemory(t *testing.T) { exercise(t, &Memory{}) }
func TestDir(t *testing.T)    { exercise(t, Dir{Path: t.TempDir()}) }

// Touches the real login Keychain under a throwaway service name, so it
// only runs when asked.
func TestKeychain(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("FLOW_REMOTE_KEYCHAIN_TEST") != "1" {
		t.Skip("set FLOW_REMOTE_KEYCHAIN_TEST=1 to test the real Keychain")
	}
	exercise(t, Keychain{Service: "flow-remote-test"})
}

// truncating behaves like `security -i`: it keeps only what fits in a
// 4096-byte command line and reports success anyway.
type truncating struct{ m map[string]string }

func (f *truncating) get(name string) (string, error) {
	v, ok := f.m[name]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *truncating) put(name, value string) error {
	prefix := len("add-generic-password -U -s flow-remote -a  -w ") + len(name)
	if keep := 4096 - prefix; len(value) > keep {
		value = value[:keep]
	}
	f.m[name] = value
	return nil
}

func (f *truncating) del(name string) error {
	if _, ok := f.m[name]; !ok {
		return ErrNotFound
	}
	delete(f.m, name)
	return nil
}

func TestKeychainFake(t *testing.T) {
	exercise(t, Keychain{Service: "flow-remote", raw: &truncating{m: map[string]string{}}})
}

// The device registry outgrew one item and was cut off; long values now
// span several items and come back whole.
func TestKeychainLongValues(t *testing.T) {
	fake := &truncating{m: map[string]string{}}
	k := Keychain{Service: "flow-remote", raw: fake}
	big := bytes.Repeat([]byte("0123456789abcdef"), 1000) // 16 KB, about 21 KB of base64
	if err := k.Put("devices", big); err != nil {
		t.Fatal(err)
	}
	if got, err := k.Get("devices"); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("long value came back wrong: %d bytes, %v", len(got), err)
	}
	if len(fake.m) < 2 {
		t.Fatalf("expected several items, got %d", len(fake.m))
	}
	// Shrinking it again leaves no stray parts behind.
	if err := k.Put("devices", []byte("small")); err != nil {
		t.Fatal(err)
	}
	if len(fake.m) != 1 {
		t.Fatalf("stale parts left: %d items", len(fake.m))
	}
	if err := k.Put("devices", big); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete("devices"); err != nil || len(fake.m) != 0 {
		t.Fatalf("delete left %d items, %v", len(fake.m), err)
	}
}

// A write that comes back different is an error, not silent damage.
func TestKeychainReadBack(t *testing.T) {
	k := Keychain{Service: "flow-remote", raw: lossy{}}
	if err := k.Put("devices", []byte("hello")); err == nil {
		t.Fatal("a write that didn't stick was reported as success")
	}
}

type lossy struct{}

func (lossy) get(string) (string, error) { return "aGk=", nil } // "hi"
func (lossy) put(string, string) error   { return nil }
func (lossy) del(string) error           { return ErrNotFound }

func TestKeychainLongReal(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("FLOW_REMOTE_KEYCHAIN_TEST") != "1" {
		t.Skip("set FLOW_REMOTE_KEYCHAIN_TEST=1 to test the real Keychain")
	}
	k := Keychain{Service: "flow-remote-test"}
	big := bytes.Repeat([]byte("0123456789abcdef"), 1000)
	if err := k.Put("long-item", big); err != nil {
		t.Fatal(err)
	}
	defer k.Delete("long-item")
	if got, err := k.Get("long-item"); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
}
