package mailbox

import (
	"net/http"
	"testing"
	"time"
)

// The header chains below are the ones measured on the live deployment.
func TestClientIP(t *testing.T) {
	cases := []struct {
		name, xff, want string
	}{
		{"through Firebase Hosting", "49.207.57.5,66.249.82.41", "49.207.57.5"},
		{"through Hosting, forged header dropped by Hosting", "49.207.57.5,66.249.82.38", "49.207.57.5"},
		{"straight to Cloud Run", "49.207.57.5", "49.207.57.5"},
		{"straight to Cloud Run, forged entries", "6.6.6.6, 7.7.7.7,49.207.57.5", "49.207.57.5"},
		{"forged trusted-looking entries on the left", "66.249.82.1, 6.6.6.6,49.207.57.5", "49.207.57.5"},
		{"only proxies", "66.249.82.1,66.249.82.2", "66.249.82.1"},
	}
	for _, c := range cases {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("X-Forwarded-For", c.xff)
		r.Header.Set("Fastly-Client-Ip", "1.2.3.4") // never trusted
		if got := clientIP(r, TrustedProxies); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
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
