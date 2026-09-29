// Package protocol defines the plaintexts sealed inside envelopes after
// pairing. web/js/app.js speaks the same JSON; docs/PROTOCOL.md lists it.
package protocol

// Phone -> Mac kinds.
const (
	KindSend = "send" // deliver Body to Task's session
	KindSync = "sync" // ask for a fresh session list
)

// Mac -> phone kinds.
const (
	KindPaired   = "paired"   // pairing confirmed on the Mac
	KindSessions = "sessions" // the live-session list
	KindStatus   = "status"   // what happened to a KindSend
	KindMail     = "mail"     // a message a session sent to the human
)

// Delivery states in a KindStatus.
const (
	Delivered = "delivered"
	Refused   = "refused"
	Failed    = "failed"
	Stale     = "stale" // waited too long in the mailbox; send it again
)

// Msg is every plaintext. Fields not used by a kind stay empty.
type Msg struct {
	Kind string `json:"kind"`

	// send, status: the phone's id for its own message, so the phone can
	// match a status to the bubble it's showing.
	ClientID string `json:"client_id,omitempty"`
	Task     string `json:"task,omitempty"`
	Body     string `json:"body,omitempty"`
	// send: the flow message id being answered. mail: what it answers.
	ReplyTo string `json:"reply_to,omitempty"`

	// status
	State  string `json:"state,omitempty"`
	Reason string `json:"reason,omitempty"`
	FlowID string `json:"flow_id,omitempty"`

	// sessions
	Sessions []Session `json:"sessions,omitempty"`

	// mail
	Mail *Mail `json:"mail,omitempty"`

	// paired
	MacName string `json:"mac_name,omitempty"`
}

type Session struct {
	Slug      string   `json:"slug"`
	Name      string   `json:"name"`
	Project   string   `json:"project,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	WaitingOn string   `json:"waiting_on,omitempty"`
	// CanSend is always true now: any paired phone may message any live
	// session. Kept for apps from before the allowlist was removed.
	CanSend bool `json:"can_send"`
}

type Mail struct {
	FlowID    string `json:"flow_id"`
	Task      string `json:"task"`
	Body      string `json:"body"`
	Urgent    bool   `json:"urgent,omitempty"`
	Broadcast bool   `json:"broadcast,omitempty"`
	CreatedAt int64  `json:"created_at"` // unix ms
	ReplyTo   string `json:"reply_to,omitempty"`
}
