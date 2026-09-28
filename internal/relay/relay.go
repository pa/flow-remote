// Package relay is the Mac side: it pulls envelopes from the mailbox,
// checks them, hands messages to flow sessions, and sends the sessions'
// mail back to the phone.
package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pa/flow-remote/internal/client"
	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/flowcli"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/protocol"
)

const (
	maxBody = 4000
	// How often the session list is re-read from flow.
	sessionsEvery = 15 * time.Second
	// Unread mail older than this isn't forwarded, so a first run doesn't
	// flood the phone with old history.
	mailHorizon = envelope.Retention
)

type Mailbox interface {
	List(ctx context.Context) (client.Batch, error)
	Post(ctx context.Context, e *envelope.Envelope) error
	Ack(ctx context.Context, ids []string) error
}

type Relay struct {
	Mac     *identity.Mac
	Devices *identity.Devices
	Guard   *envelope.Guard
	Mailbox Mailbox
	Flow    flowcli.Flow
	Allow   *Allowlist
	State   *State
	Audit   io.Writer
	Log     *slog.Logger
	Now     func() time.Time

	sessionsHash string
	sessionsAt   time.Time
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Tick does one round and returns how long to wait before the next.
func (r *Relay) Tick(ctx context.Context) (time.Duration, error) {
	batch, err := r.Mailbox.List(ctx)
	if err != nil {
		return time.Minute, err
	}
	var acks []string
	forceSessions := false
	for _, rec := range batch.Envelopes {
		if r.handle(ctx, rec.Env, &forceSessions) {
			acks = append(acks, rec.Env.ID)
		}
	}
	if err := r.Mailbox.Ack(ctx, acks); err != nil {
		r.log("ack failed", "err", err)
	}
	if err := r.syncSessions(ctx, forceSessions); err != nil {
		r.log("sessions", "err", err)
	}
	if err := r.forwardMail(ctx); err != nil {
		r.log("mail", "err", err)
	}
	poll := time.Duration(batch.PollMS) * time.Millisecond
	if poll <= 0 {
		poll = time.Minute
	}
	return poll, nil
}

// handle processes one envelope and reports whether to ack it. Envelopes
// that fail checks are acked too, so junk doesn't come back every poll.
func (r *Relay) handle(ctx context.Context, e envelope.Envelope, forceSessions *bool) bool {
	dev, ok := r.Devices.Active(e.From)
	if !ok {
		r.audit("drop", e.From, "", "unknown or revoked device")
		return true
	}
	pub, err := envelope.ParseSignPub(dev.SignPub)
	if err != nil || envelope.Verify(&e, pub) != nil {
		r.audit("drop", dev.ID, "", "bad signature")
		return true
	}
	if err := r.Guard.Admit(&e, r.now()); err != nil {
		r.audit("drop", dev.ID, "", err.Error())
		return true
	}
	pt, err := envelope.Open(&e, r.Mac.Box)
	if err != nil {
		r.audit("drop", dev.ID, "", "cannot open")
		return true
	}
	var m protocol.Msg
	if err := json.Unmarshal(pt, &m); err != nil {
		r.audit("drop", dev.ID, "", "bad payload")
		return true
	}
	switch m.Kind {
	case protocol.KindSync:
		*forceSessions = true
	case protocol.KindSend:
		st := r.deliver(ctx, dev, e, m)
		st.Kind, st.ClientID, st.Task = protocol.KindStatus, m.ClientID, m.Task
		if err := r.sendTo(ctx, dev, st); err != nil {
			r.log("status", "err", err)
		}
	default:
		r.audit("drop", dev.ID, m.Task, "unknown kind "+m.Kind)
	}
	return true
}

func (r *Relay) deliver(ctx context.Context, dev identity.Device, e envelope.Envelope, m protocol.Msg) protocol.Msg {
	refuse := func(reason string) protocol.Msg {
		r.audit("refuse", dev.ID, m.Task, reason)
		return protocol.Msg{State: protocol.Refused, Reason: reason}
	}
	if !flowcli.ValidSlug(m.Task) {
		return refuse("not a task slug")
	}
	if m.Body == "" || utf8.RuneCountInString(m.Body) > maxBody {
		return refuse(fmt.Sprintf("message must be 1-%d characters", maxBody))
	}
	tasks, err := r.Flow.LiveTasks(ctx)
	if err != nil {
		r.audit("fail", dev.ID, m.Task, err.Error())
		return protocol.Msg{State: protocol.Failed, Reason: "couldn't read flow's task list"}
	}
	var task *flowcli.Task
	for i := range tasks {
		if tasks[i].Slug == m.Task {
			task = &tasks[i]
		}
	}
	if task == nil {
		return refuse("that session isn't running on the Mac")
	}
	if !r.Allow.Allows(task.Slug, task.Tags) {
		return refuse("the Mac's allowlist doesn't include this session")
	}
	body := fmt.Sprintf("[phone · %s] %s", age(r.now().Sub(time.UnixMilli(e.TS))), m.Body)
	id, err := r.Flow.Message(ctx, task.Slug, body, m.ReplyTo)
	if err != nil {
		r.audit("fail", dev.ID, m.Task, err.Error())
		return protocol.Msg{State: protocol.Failed, Reason: "flow couldn't deliver it"}
	}
	// Answering a session's message from the phone counts as reading it.
	if m.ReplyTo != "" {
		if err := r.Flow.MarkRead(ctx, m.ReplyTo); err != nil {
			r.log("mark read", "id", m.ReplyTo, "err", err)
		}
	}
	r.audit("deliver", dev.ID, m.Task, id)
	return protocol.Msg{State: protocol.Delivered, FlowID: id}
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("sent %dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("sent %dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("sent %dd %dh ago", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func (r *Relay) syncSessions(ctx context.Context, force bool) error {
	if !force && r.now().Sub(r.sessionsAt) < sessionsEvery {
		return nil
	}
	r.sessionsAt = r.now()
	tasks, err := r.Flow.LiveTasks(ctx)
	if err != nil {
		return err
	}
	sessions := make([]protocol.Session, 0, len(tasks))
	for _, t := range tasks {
		sessions = append(sessions, protocol.Session{
			Slug: t.Slug, Name: t.Name, Project: t.Project, Tags: t.Tags,
			WaitingOn: t.WaitingOn, CanSend: r.Allow.Allows(t.Slug, t.Tags),
		})
	}
	b, _ := json.Marshal(sessions)
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	if !force && h == r.sessionsHash {
		return nil
	}
	r.sessionsHash = h
	return r.broadcast(ctx, protocol.Msg{Kind: protocol.KindSessions, Sessions: sessions})
}

func (r *Relay) forwardMail(ctx context.Context) error {
	mail, err := r.Flow.Unread(ctx)
	if err != nil {
		return err
	}
	for _, m := range mail {
		if m.From.TaskSlug == "" || r.State.Forwarded(m.ID) || r.now().Sub(m.CreatedAt) > mailHorizon {
			continue
		}
		msg := protocol.Msg{Kind: protocol.KindMail, Mail: &protocol.Mail{
			FlowID: m.ID, Task: m.From.TaskSlug, Body: m.Body, Urgent: m.Urgent,
			Broadcast: m.Kind == "broadcast", CreatedAt: m.CreatedAt.UnixMilli(), ReplyTo: m.ReplyTo,
		}}
		if err := r.broadcast(ctx, msg); err != nil {
			return err
		}
		if err := r.State.MarkForwarded(m.ID, r.now()); err != nil {
			return err
		}
		r.audit("forward", "", m.From.TaskSlug, m.ID)
	}
	return nil
}

func (r *Relay) broadcast(ctx context.Context, m protocol.Msg) error {
	var errs []error
	for _, dev := range r.Devices.List() {
		if !dev.Revoked() {
			errs = append(errs, r.sendTo(ctx, dev, m))
		}
	}
	return errors.Join(errs...)
}

func (r *Relay) sendTo(ctx context.Context, dev identity.Device, m protocol.Msg) error {
	box, err := envelope.ParseBoxPub(dev.BoxPub)
	if err != nil {
		return err
	}
	pt, _ := json.Marshal(m)
	e, err := envelope.Seal(pt, r.Mac.Sign, r.Mac.ID, dev.ID, box, r.now().UnixMilli())
	if err != nil {
		return err
	}
	return r.Mailbox.Post(ctx, e)
}

// SendTo seals m to one device. Used by pairing to send the welcome.
func (r *Relay) SendTo(ctx context.Context, dev identity.Device, m protocol.Msg) error {
	return r.sendTo(ctx, dev, m)
}

func (r *Relay) log(msg string, args ...any) {
	if r.Log != nil {
		r.Log.Warn(msg, args...)
	}
}

// audit appends one JSON line per decision. Message bodies are never logged.
func (r *Relay) audit(action, device, task, detail string) {
	if r.Audit == nil {
		return
	}
	line, _ := json.Marshal(map[string]string{
		"at": r.now().Format(time.RFC3339), "action": action, "device": device, "task": task, "detail": detail,
	})
	r.Audit.Write(append(line, '\n'))
}

// State remembers which flow mail has gone to the phone, so the relay can
// read the human's queue without acking it.
type State struct {
	mu        sync.Mutex
	path      string
	forwarded map[string]time.Time
}

func LoadState(path string) (*State, error) {
	s := &State{path: path, forwarded: map[string]time.Time{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, &s.forwarded)
}

func (s *State) Forwarded(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.forwarded[id]
	return ok
}

func (s *State) MarkForwarded(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwarded[id] = now
	for k, t := range s.forwarded {
		if now.Sub(t) > 2*mailHorizon {
			delete(s.forwarded, k)
		}
	}
	if s.path == "" {
		return nil
	}
	b, _ := json.Marshal(s.forwarded)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
