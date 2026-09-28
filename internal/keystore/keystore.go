// Package keystore holds the relay's secrets: the Mac's private keys and
// the enrolled-device registry. On the Mac that's the login Keychain.
package keystore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ErrNotFound means the item doesn't exist yet.
var ErrNotFound = errors.New("keystore: not found")

type Store interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func checkName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("keystore: bad item name %q", name)
	}
	return nil
}

// Keychain stores items as generic passwords under one service name.
// Values are base64-encoded so they never need quoting.
type Keychain struct {
	Service string // e.g. "flow-remote"
}

func (k Keychain) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", k.Service, "-a", name, "-w")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// security exits 44 when the item is missing.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keychain get %s: %v: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(stdout.String()))
}

// Put writes through `security -i` on stdin, so the value never appears in
// the process list the way a -w argument would.
func (k Keychain) Put(name string, value []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkName(k.Service); err != nil {
		return err
	}
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		k.Service, name, base64.StdEncoding.EncodeToString(value))
	var stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(line)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	// -i mode exits 0 even when a command fails, so check what it printed.
	msg := strings.TrimSpace(string(out) + stderr.String())
	if err != nil || msg != "" {
		return fmt.Errorf("keychain put %s: %v %s", name, err, msg)
	}
	return nil
}

func (k Keychain) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", k.Service, "-a", name)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return ErrNotFound
		}
		return fmt.Errorf("keychain delete %s: %v", name, err)
	}
	return nil
}

// Dir stores each item as a 0600 file. For tests and for machines without
// a Keychain; the relay uses Keychain on macOS.
type Dir struct{ Path string }

func (d Dir) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (d Dir) Put(name string, value []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(d.Path, name+".tmp")
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d.Path, name))
}

func (d Dir) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(d.Path, name))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// Memory is an in-process store for tests.
type Memory struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *Memory) Get(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(v), nil
}

func (s *Memory) Put(name string, value []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[name] = bytes.Clone(value)
	return nil
}

func (s *Memory) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; !ok {
		return ErrNotFound
	}
	delete(s.m, name)
	return nil
}
