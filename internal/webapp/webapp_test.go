package webapp

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/pa/flow-remote/web"
)

func TestServesEmbeddedApp(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := Handler(api, web.Files)
	for path, want := range map[string]int{
		"/": 200, "/js/app.js": 200, "/sw.js": 200, "/vendor/jsqr-1.4.0/jsQR.js": 200,
		"/js/fuzzy.test.mjs": 404, "/v1/anything": http.StatusTeapot,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s = %d, want %d", path, rec.Code, want)
		}
		if want == 200 && rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: missing security headers", path)
		}
	}
}

// Everything the service worker precaches must be in the binary, or the
// install fails on the phone.
func TestShellIsEmbedded(t *testing.T) {
	sw, err := fs.ReadFile(web.Files, "sw.js")
	if err != nil {
		t.Fatal(err)
	}
	shell := regexp.MustCompile(`(?s)const SHELL = \[(.*?)\];`).FindSubmatch(sw)
	if shell == nil {
		t.Fatal("no SHELL list in sw.js")
	}
	for _, m := range regexp.MustCompile(`"\./([^"]*)"`).FindAllSubmatch(shell[1], -1) {
		name := string(m[1])
		if name == "" {
			continue // "./" is index.html
		}
		if _, err := fs.Stat(web.Files, name); err != nil {
			t.Errorf("sw.js precaches %s, which isn't embedded", name)
		}
	}
}
