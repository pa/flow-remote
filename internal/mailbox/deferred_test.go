package mailbox

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeferredStartsServingBeforeTheStore(t *testing.T) {
	d := &Deferred{}
	srv := httptest.NewServer((&Server{Store: d, Ready: d.Ready}).Handler())
	defer srv.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		b.Write(buf[:n])
		return resp.StatusCode, b.String()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := make(chan struct{}, 10)
	var fail atomic.Bool
	fail.Store(true)
	go d.Connect(ctx, func(context.Context) (Store, error) {
		attempts <- struct{}{}
		if fail.Load() {
			return nil, errors.New("auth: permission denied")
		}
		return NewMemory(), nil
	}, nil)
	<-attempts

	if code, body := get("/healthz"); code != http.StatusServiceUnavailable || !strings.Contains(body, "permission denied") {
		t.Fatalf("healthz before connect: %d %s", code, body)
	}
	if code, _ := get("/v1/envelopes"); code != http.StatusServiceUnavailable {
		t.Fatalf("api before connect: %d", code)
	}

	fail.Store(false)
	<-attempts // the retry after a 1s wait
	deadline := time.Now().Add(2 * time.Second)
	for d.Ready() != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if code, body := get("/healthz"); code != http.StatusOK {
		t.Fatalf("healthz after connect: %d %s", code, body)
	}
	if code, _ := get("/v1/envelopes"); code != http.StatusUnauthorized {
		t.Fatalf("api after connect, unsigned: %d", code)
	}
}
