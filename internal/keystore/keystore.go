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
	"strconv"
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
//
// Writes go through `security -i`, which reads each command into a
// 4096-byte line buffer and silently drops the rest. So a long value is
// split: the head item holds "chunks:<n>:" and the first part, and items
// <name>.1 to <name>.<n-1> hold the rest. base64 has no ':', so a value
// that fits in one item can't be mistaken for a head. Every Put reads the
// value back and fails if it doesn't match.
type Keychain struct {
	Service string // e.g. "flow-remote"
	raw     rawStore
}

const (
	chunkSize   = 3000 // base64 characters per item, well under the line limit
	chunkPrefix = "chunks:"
	maxLine     = 4000 // refuse rather than let security truncate
)

type rawStore interface {
	get(name string) (string, error)
	put(name, value string) error
	del(name string) error
}

func (k Keychain) store() rawStore {
	if k.raw != nil {
		return k.raw
	}
	return securityCLI{k.Service}
}

func (k Keychain) Get(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	raw := k.store()
	head, err := raw.get(name)
	if err != nil {
		return nil, err
	}
	enc := head
	if rest, ok := strings.CutPrefix(head, chunkPrefix); ok {
		count, first, ok := strings.Cut(rest, ":")
		n, err := strconv.Atoi(count)
		if !ok || err != nil || n < 2 {
			return nil, fmt.Errorf("keychain get %s: bad chunk header", name)
		}
		var b strings.Builder
		b.WriteString(first)
		for i := 1; i < n; i++ {
			part, err := raw.get(chunkName(name, i))
			if err != nil {
				return nil, fmt.Errorf("keychain get %s: part %d of %d: %w", name, i+1, n, err)
			}
			b.WriteString(part)
		}
		enc = b.String()
	}
	return base64.StdEncoding.DecodeString(enc)
}

func (k Keychain) Put(name string, value []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkName(k.Service); err != nil {
		return err
	}
	raw := k.store()
	parts := chunks(base64.StdEncoding.EncodeToString(value))
	if err := putParts(raw, name, parts); err != nil {
		return err
	}
	// Drop parts left over from an earlier, longer value.
	for i := len(parts); ; i++ {
		if err := raw.del(chunkName(name, i)); err != nil {
			break
		}
	}
	got, err := k.Get(name)
	if err != nil || !bytes.Equal(got, value) {
		return fmt.Errorf("keychain put %s: read-back didn't match what was written (%v)", name, err)
	}
	return nil
}

// chunks splits enc into pieces of at most chunkSize, the most one
// Keychain item holds reliably.
func chunks(enc string) []string {
	var parts []string
	for len(enc) > chunkSize {
		parts, enc = append(parts, enc[:chunkSize]), enc[chunkSize:]
	}
	return append(parts, enc)
}

// putParts writes a value split into parts: one part as is, several as a
// head naming the count followed by numbered items. The numbered items go
// first, so a reader never sees a head pointing at parts not written yet.
func putParts(raw rawStore, name string, parts []string) error {
	if len(parts) == 1 {
		return raw.put(name, parts[0])
	}
	for i := 1; i < len(parts); i++ {
		if err := raw.put(chunkName(name, i), parts[i]); err != nil {
			return err
		}
	}
	return raw.put(name, fmt.Sprintf("%s%d:%s", chunkPrefix, len(parts), parts[0]))
}

func (k Keychain) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	raw := k.store()
	if err := raw.del(name); err != nil {
		return err
	}
	for i := 1; ; i++ {
		if err := raw.del(chunkName(name, i)); err != nil {
			break
		}
	}
	return nil
}

func chunkName(name string, i int) string { return name + "." + strconv.Itoa(i) }

// securityCLI is the login Keychain, through /usr/bin/security.
type securityCLI struct{ service string }

func (c securityCLI) get(name string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", c.service, "-a", name, "-w")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// security exits 44 when the item is missing.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keychain get %s: %v: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// put writes through `security -i` on stdin, so the value never appears in
// the process list the way a -w argument would.
func (c securityCLI) put(name, value string) error {
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", c.service, name, value)
	if len(line) > maxLine {
		return fmt.Errorf("keychain put %s: %d-byte command is too long for security -i", name, len(line))
	}
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

func (c securityCLI) del(name string) error {
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", c.service, "-a", name)
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
