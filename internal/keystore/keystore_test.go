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
