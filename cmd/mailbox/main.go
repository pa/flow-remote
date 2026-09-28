// Command mailbox is the Cloud Run service between the phone and the Mac.
//
//	mailbox           serve on $PORT
//	mailbox cleanup   delete expired envelopes and exit (the scheduled job)
//
// Configuration comes from the environment:
//
//	MAILBOX_SETUP_TOKEN   registers the first, admin Mac (`flow-remote setup`).
//	                      Clear it afterwards; invites cover every other Mac.
//	MAILBOX_STORE         "memory" (default) or "mongo"
//	MAILBOX_MONGO_URI     connection string, for "mongo"
//	MAILBOX_MONGO_DB      database name (default: the one in the URI's path;
//	                      Firestore's MongoDB mode only accepts its own
//	                      database id there)
//	MAILBOX_WEB_DIR       also serve the phone app from this directory.
//	                      Firebase Hosting only forwards to Cloud Run, so
//	                      on GCP the image bakes the app in at /web.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"

	"github.com/pa/flow-remote/internal/mailbox"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("mailbox", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		store, err := openStore(ctx)
		if err != nil {
			return err
		}
		n, err := store.DeleteExpired(ctx, time.Now())
		log.Info("cleanup", "deleted", n)
		return err
	}

	// Connect in the background: Cloud Run replaces a container that
	// doesn't listen on $PORT within its startup window, so a slow or
	// failing first database connection must not stop the server starting.
	store := &mailbox.Deferred{}
	go store.Connect(ctx, openStore, func(err error) { log.Warn("store connect", "err", err) })
	s := &mailbox.Server{Store: store, Ready: store.Ready, SetupToken: os.Getenv("MAILBOX_SETUP_TOKEN"), Log: log}
	if s.SetupToken != "" && len(s.SetupToken) < 24 {
		return errors.New("MAILBOX_SETUP_TOKEN must be at least 24 characters")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	handler := s.Handler()
	if dir := os.Getenv("MAILBOX_WEB_DIR"); dir != "" {
		handler = withApp(handler, dir)
	}
	srv := &http.Server{Addr: "0.0.0.0:" + port, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("listening", "port", port)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// withApp serves the phone app next to the API.
func withApp(api http.Handler, dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	mux := http.NewServeMux()
	mux.Handle("/v1/", api)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Revalidate on every load, so the CDN and the service worker
		// pick up a deploy right away.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		files.ServeHTTP(w, r)
	})
	return mux
}

func openStore(ctx context.Context) (mailbox.Store, error) {
	switch kind := os.Getenv("MAILBOX_STORE"); kind {
	case "", "memory":
		if os.Getenv("K_SERVICE") != "" {
			// Cloud Run scales to zero and would drop every envelope.
			return nil, errors.New("MAILBOX_STORE=memory loses data on Cloud Run; use mongo")
		}
		return mailbox.NewMemory(), nil
	case "mongo":
		uri := os.Getenv("MAILBOX_MONGO_URI")
		if uri == "" {
			return nil, errors.New("MAILBOX_MONGO_URI is required for MAILBOX_STORE=mongo")
		}
		name := os.Getenv("MAILBOX_MONGO_DB")
		if name == "" {
			cs, err := connstring.Parse(uri)
			if err != nil {
				return nil, fmt.Errorf("MAILBOX_MONGO_URI: %w", err)
			}
			name = cs.Database
		}
		if name == "" {
			name = "flowremote"
		}
		m, err := mailbox.OpenMongo(ctx, uri, name)
		if err == nil && m.IndexErr != nil {
			slog.Warn("indexes not created; queries run without them", "err", m.IndexErr)
		}
		return m, err
	default:
		return nil, fmt.Errorf("MAILBOX_STORE=%q: want memory or mongo", kind)
	}
}
