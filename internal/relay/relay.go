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
	"strings"
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
	minPoll = time.Second
	maxPoll = 5 * time.Minute
	// A phone message that waited longer than this isn't delivered; the phone
	// is told and can send it again. A compromised mailbox could otherwise
	// hold a "yes, go ahead" and release it at a moment of its choosing.
	staleAfter = 10 * time.Minute

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
	devicesAt    time.Time // last registry re-read
	devicesSeen  string    // active device ids when the list last went out
}

// activeDevices is the enrolled, unrevoked device ids, as one string.
func (r *Relay) activeDevices() string {
	var ids []string
	for _, d := range r.Devices.List() {
		if !d.Revoked() {
			ids = append(ids, d.ID)
		}
	}
	return strings.Join(ids, ",")
}

const (
	// The registry is re-read this often, and right away (at most every
	// reloadMin) when a message comes from a device we don't know. Pairing
	// runs in a separate process, so a running relay has to look again.
	reloadEvery = 15 * time.Second
	reloadMin   = 2 * time.Second
)

// reloadDevices re-reads the registry unless it was read within minAge,
// and reports whether it did.
func (r *Relay) reloadDevices(minAge time.Duration) bool {
	if r.now().Sub(r.devicesAt) < minAge {
		return false
	}
	r.devicesAt = r.now()
	if err := r.Devices.Reload(); err != nil {
		r.log("reload devices", "err", err)
	}
	return true
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Tick does one round and returns how long to wait before the next.
func (r *Relay) Tick(ctx context.Context) (time.Duration, error) {
	r.reloadDevices(reloadEvery)
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
	// A phone paired since the last list went out gets one now, not when
	// the sessions next change.
	if devs := r.activeDevices(); devs != r.devicesSeen {
		r.devicesSeen, forceSessions = devs, true
	}
	if err := r.syncSessions(ctx, forceSessions); err != nil {
		r.log("sessions", "err", err)
	}
	if err := r.forwardMail(ctx); err != nil {
		r.log("mail", "err", err)
	}
	// The mailbox suggests the interval, but it's untrusted: a hostile one
	// could otherwise pin the Mac forking `flow` in a tight loop.
	poll := min(max(time.Duration(batch.PollMS)*time.Millisecond, minPoll), maxPoll)
	return poll, nil
}

// handle processes one envelope and reports whether to ack it. Envelopes
// that fail checks are acked too, so junk doesn't come back every poll.
func (r *Relay) handle(ctx context.Context, e envelope.Envelope, forceSessions *bool) bool {
	if e.To != r.Mac.ID {
		r.audit("drop", e.From, "", "addressed to another Mac")
		return true
	}
	dev, ok := r.Devices.Active(e.From)
	if !ok {
		reloaded := r.reloadDevices(reloadMin)
		dev, ok = r.Devices.Active(e.From)
		if !ok && !reloaded {
			// Maybe a phone paired a moment ago and the registry was read
			// just before. Leave it for the next round, which reads it again,
			// rather than dropping the phone's first message.
			return false
		}
	}
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
	if waited := r.now().Sub(time.UnixMilli(e.TS)); waited > staleAfter {
		r.audit("stale", dev.ID, m.Task, age(waited))
		return protocol.Msg{State: protocol.Stale, Reason: fmt.Sprintf("it waited %s while the Mac was away", strings.TrimPrefix(age(waited), "sent "))}
	}
	// A reply may only answer mail this relay forwarded from that session,
	// so a phone can't mark other sessions' mail read or pass arbitrary
	// text to flow's --reply-to.
	if m.ReplyTo != "" && r.State.ForwardedFrom(m.ReplyTo) != m.Task {
		return refuse("that reply doesn't match a message from this session")
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
		if err := r.State.MarkForwarded(m.ID, m.From.TaskSlug, r.now()); err != nil {
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

// State remembers which flow mail has gone to the phone, and from which
// session, so the relay can read the human's queue without acking it and
// check that a reply answers a message it actually forwarded.
type State struct {
	mu        sync.Mutex
	path      string
	forwarded map[string]forward
}

type forward struct {
	At   time.Time `json:"at"`
	Task string    `json:"task"`
}

func LoadState(path string) (*State, error) {
	s := &State{path: path, forwarded: map[string]forward{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.forwarded); err == nil {
		return s, nil
	}
	// Before the session was recorded, the file held id -> time.
	var old map[string]time.Time
	if err := json.Unmarshal(b, &old); err != nil {
		return nil, err
	}
	for id, t := range old {
		s.forwarded[id] = forward{At: t}
	}
	return s, nil
}

func (s *State) Forwarded(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.forwarded[id]
	return ok
}

// ForwardedFrom returns the session a forwarded message came from, or "".
func (s *State) ForwardedFrom(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forwarded[id].Task
}

func (s *State) MarkForwarded(id, task string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwarded[id] = forward{At: now, Task: task}
	for k, f := range s.forwarded {
		if now.Sub(f.At) > 2*mailHorizon {
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

// maxBackoff caps the wait between retries while the mailbox is
// unreachable (Wi-Fi down, Mac asleep), so the relay is back within this
// long of the network returning.
const maxBackoff = 30 * time.Second

// Loop runs Tick until ctx ends. A receive on wake starts the next round
// at once: `flow-remote serve` signals it when a phone posts, so messages
// don't wait for the poll interval.
func (r *Relay) Loop(ctx context.Context, wake <-chan struct{}) error {
	backoff := time.Second
	for {
		wait, err := r.Tick(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.log("tick", "err", err)
			wait, backoff = backoff, min(backoff*2, maxBackoff)
		} else {
			backoff = time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-wake:
			t.Stop()
		case <-t.C:
		}
	}
}
