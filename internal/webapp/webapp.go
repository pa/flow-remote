// Package webapp serves the phone app next to an API, with the headers
// both the mailbox container and `flow-remote serve` use.
package webapp

import (
	"io/fs"
	"net/http"
)

// Handler sends /v1/ to api and everything else to the app's files.
func Handler(api http.Handler, files fs.FS) http.Handler {
	static := http.FileServer(http.FS(files))
	mux := http.NewServeMux()
	mux.Handle("/v1/", api)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Revalidate on every load, so the service worker picks up a new
		// build right away.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		static.ServeHTTP(w, r)
	})
	return mux
}
