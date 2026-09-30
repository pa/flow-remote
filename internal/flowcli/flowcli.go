// Package flowcli runs the flow CLI for the relay. Arguments go straight
// to exec with no shell, so a message body can never become a command.
package flowcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Task is the part of `flow list tasks --format json` the relay uses.
type Task struct {
	Slug      string   `json:"slug"`
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Project   string   `json:"project"`
	Tags      []string `json:"tags"`
	WaitingOn string   `json:"waiting_on"`
	Live      bool     `json:"live"`
}

// Mail is one entry of `flow inbox --json`.
type Mail struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Kind      string    `json:"kind"` // "message" or "broadcast"
	From      Address   `json:"from"`
	To        Address   `json:"to"`
	Body      string    `json:"body"`
	Urgent    bool      `json:"urgent"`
	ReplyTo   string    `json:"reply_to"`
	Mail      string    `json:"mail"` // "unread" or "read"
}

type Address struct {
	Assignee string `json:"assignee"`
	TaskSlug string `json:"task_slug"`
}

// Flow is what the relay needs from flow. The real one is CLI; tests fake it.
type Flow interface {
	LiveTasks(ctx context.Context) ([]Task, error)
	// Message sends body to a task's session and returns flow's message id.
	Message(ctx context.Context, slug, body, replyTo string) (string, error)
	// Inbox lists the human's mail, read or not, without consuming it.
	Inbox(ctx context.Context) ([]Mail, error)
	// MarkRead acks one message in the human's queue.
	MarkRead(ctx context.Context, id string) error
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,79}$`)

// ValidSlug is the check the relay applies before a slug reaches flow.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

type CLI struct {
	Bin     string // defaults to "flow" on PATH
	Timeout time.Duration
}

// env drops the harness session variables. flow works out who a message is
// from by looking up the active harness session, and the relay speaks as
// the human, not as whatever session happened to start it.
func env() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT":
			continue
		}
		out = append(out, kv)
	}
	return out
}

func (c CLI) run(ctx context.Context, args ...string) ([]byte, error) {
	bin := c.Bin
	if bin == "" {
		bin = "flow"
	}
	to := c.Timeout
	if to == 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("flow %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (c CLI) LiveTasks(ctx context.Context) ([]Task, error) {
	out, err := c.run(ctx, "list", "tasks", "--format", "json")
	if err != nil {
		return nil, err
	}
	var all []Task
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, fmt.Errorf("flow list tasks: %w", err)
	}
	live := all[:0]
	for _, t := range all {
		if t.Live {
			live = append(live, t)
		}
	}
	return live, nil
}

var sentID = regexp.MustCompile(`\[([0-9a-f]{6,})\]`)

func (c CLI) Message(ctx context.Context, slug, body, replyTo string) (string, error) {
	if !ValidSlug(slug) {
		return "", fmt.Errorf("bad task slug %q", slug)
	}
	// --body keeps a body that starts with "-" from being read as a flag.
	args := []string{"message", "user/" + slug, "--body", body}
	if replyTo != "" {
		args = append(args, "--reply-to", replyTo)
	}
	out, err := c.run(ctx, args...)
	if err != nil {
		return "", err
	}
	m := sentID.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("flow message: no id in %q", strings.TrimSpace(string(out)))
	}
	return string(m[1]), nil
}

// Inbox includes mail already read: anything else reading the human's
// queue (another session's `flow inbox pop`, say) marks it read, and a
// session's reply must still reach the phone.
func (c CLI) Inbox(ctx context.Context) ([]Mail, error) {
	out, err := c.run(ctx, "inbox", "--as", "user", "--all", "--json")
	if err != nil {
		return nil, err
	}
	var mail []Mail
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(out, &mail); err != nil {
		return nil, fmt.Errorf("flow inbox: %w", err)
	}
	return mail, nil
}

var idRE = regexp.MustCompile(`^[0-9a-f]{6,32}$`)

func (c CLI) MarkRead(ctx context.Context, id string) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("bad message id %q", id)
	}
	_, err := c.run(ctx, "inbox", "read", id)
	return err
}
