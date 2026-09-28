package relay

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const defaultAllow = `# Sessions the phone may send messages to. One rule per line:
#   a task slug       phone-dispatch
#   a tag             #personal
#   every live one    *
# Every live session is still listed on the phone; the rest are read-only.
# Customer tasks don't belong here until Phase 2's policy adds Ask-only mode.
phone-dispatch
`

// Allowlist is the Phase 1 stand-in for policy.yaml.
type Allowlist struct {
	all   bool
	slugs map[string]bool
	tags  map[string]bool
}

// LoadAllowlist reads path, writing the default file on first run.
func LoadAllowlist(path string) (*Allowlist, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(defaultAllow), 0o600); err != nil {
			return nil, err
		}
		b = []byte(defaultAllow)
	} else if err != nil {
		return nil, err
	}
	return ParseAllowlist(string(b)), nil
}

func ParseAllowlist(text string) *Allowlist {
	a := &Allowlist{slugs: map[string]bool{}, tags: map[string]bool{}}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "# ") || line == "#" {
			continue
		}
		if line == "*" {
			a.all = true
		} else if tag, ok := strings.CutPrefix(line, "#"); ok {
			a.tags[tag] = true
		} else {
			a.slugs[line] = true
		}
	}
	return a
}

func (a *Allowlist) Allows(slug string, tags []string) bool {
	if a.all || a.slugs[slug] {
		return true
	}
	return slices.ContainsFunc(tags, func(t string) bool { return a.tags[t] })
}
