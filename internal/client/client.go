// Package client is the relay's side of the mailbox API. Every call is
// signed with the Mac's sign key.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pa/flow-remote/internal/envelope"
	"github.com/pa/flow-remote/internal/identity"
	"github.com/pa/flow-remote/internal/reqsig"
)

var ErrNotFound = errors.New("client: not found")

type Client struct {
	BaseURL string
	Mac     *identity.Mac
	HTTP    *http.Client
	Now     func() time.Time
}

// Record mirrors mailbox.Record's JSON.
type Record struct {
	Env        envelope.Envelope `json:"env"`
	Seq        int64             `json:"seq"`
	ReceivedAt time.Time         `json:"received_at"`
}

type Batch struct {
	Envelopes []Record `json:"envelopes"`
	PollMS    int64    `json:"poll_ms"`
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) do(ctx context.Context, method, path string, body any, signed bool, out any) error {
	return c.doWith(ctx, method, path, body, signed, nil, out)
}

func (c *Client) doWith(ctx context.Context, method, path string, body any, signed bool, hdr http.Header, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if signed {
		if err := reqsig.Sign(req, c.Mac.ID, c.Mac.Sign, raw, c.now()); err != nil {
			return err
		}
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		json.Unmarshal(data, &e)
		return fmt.Errorf("mailbox %s %s: %d %s", method, path, resp.StatusCode, e.Error)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Register binds this Mac's id to its key at the mailbox. setupToken is
// the mailbox's MAILBOX_SETUP_TOKEN; it's only needed once.
func (c *Client) Register(ctx context.Context, setupToken string) error {
	hdr := http.Header{}
	hdr.Set("X-FR-Setup", setupToken)
	return c.doWith(ctx, "POST", "/v1/macs", map[string]string{"mac_id": c.Mac.ID, "sign_pub": c.Mac.SignPub()}, true, hdr, nil)
}

// OpenPair lets the phone post one enrollment for pairID.
func (c *Client) OpenPair(ctx context.Context, pairID string) error {
	return c.do(ctx, "POST", "/v1/relay/pairs", map[string]string{"pair_id": pairID}, true, nil)
}

// TakePair fetches the phone's enrollment for pairID, or ErrNotFound if it
// hasn't arrived yet.
func (c *Client) TakePair(ctx context.Context, pairID string) (*envelope.Envelope, error) {
	var e envelope.Envelope
	if err := c.do(ctx, "GET", "/v1/relay/pairs/"+pairID, nil, true, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// PutDevice lets the mailbox accept requests signed by this device.
func (c *Client) PutDevice(ctx context.Context, dev identity.Device) error {
	return c.do(ctx, "POST", "/v1/relay/devices", map[string]string{"device_id": dev.ID, "sign_pub": dev.SignPub}, true, nil)
}

func (c *Client) RevokeDevice(ctx context.Context, deviceID string) error {
	return c.do(ctx, "POST", "/v1/relay/devices/"+deviceID+"/revoke", nil, true, nil)
}

func (c *Client) List(ctx context.Context) (Batch, error) {
	var b Batch
	err := c.do(ctx, "GET", "/v1/relay/envelopes", nil, true, &b)
	return b, err
}

func (c *Client) Post(ctx context.Context, e *envelope.Envelope) error {
	return c.do(ctx, "POST", "/v1/relay/envelopes", e, true, nil)
}

func (c *Client) Ack(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return c.do(ctx, "POST", "/v1/relay/ack", map[string]any{"ids": ids}, true, nil)
}
