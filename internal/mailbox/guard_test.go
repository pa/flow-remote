package mailbox

import (
	"net/http"
	"testing"
	"time"
)

// A client's own address is what's limited; a header naming another
// address is ignored, so it can't dodge its budget.
func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.7:59289"
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := clientIP(r); got != "100.64.0.7" {
		t.Fatalf("clientIP = %s", got)
	}
}

func TestIPBucketsAreBounded(t *testing.T) {
	var l ipLimiter
	now := time.Now()
	for i := 0; i < maxIPBuckets+1000; i++ {
		l.allow(string(rune(i))+"ip", now)
	}
	if len(l.buckets) > maxIPBuckets+1 {
		t.Fatalf("%d buckets", len(l.buckets))
	}
}
