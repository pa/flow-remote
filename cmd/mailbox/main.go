// Command mailbox is the Cloud Run service between the phone and the Mac.
//
//	mailbox           serve on $PORT
//	mailbox cleanup   delete expired envelopes and exit (the scheduled job)
//
// Configuration comes from the environment:
//
//	MAILBOX_OWNER         the one Google account allowed in (required)
//	FIREBASE_PROJECT_ID   project whose ID tokens are accepted
//	FIREBASE_TENANT_ID    Identity Platform tenant, if the app has one
//	MAILBOX_STORE         "memory" (default) or "mongo"
//	MAILBOX_MONGO_URI     connection string, for "mongo"
//	MAILBOX_MONGO_DB      database name (default "flow-remote")
//	MAILBOX_DEV_AUTH=1    accept "Bearer dev:<email>" (local only)
//	MAILBOX_WEB_DIR       also serve the phone app from this directory
//	                      (local only; on GCP, Firebase Hosting serves it)
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

	store, err := openStore(ctx)
	if err != nil {
		return err
	}
	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		n, err := store.DeleteExpired(ctx, time.Now())
		log.Info("cleanup", "deleted", n)
		return err
	}

	s := &mailbox.Server{Store: store, Owner: os.Getenv("MAILBOX_OWNER"), Log: log}
	if s.Owner == "" {
		return errors.New("MAILBOX_OWNER is required")
	}
	if os.Getenv("MAILBOX_DEV_AUTH") == "1" {
		// K_SERVICE is set on every Cloud Run service.
		if os.Getenv("K_SERVICE") != "" {
			return errors.New("MAILBOX_DEV_AUTH must never be set on Cloud Run")
		}
		s.DevAuth = true
		log.Warn("dev auth on: any 'Bearer dev:<email>' is trusted")
	}
	if p := os.Getenv("FIREBASE_PROJECT_ID"); p != "" {
		s.Tokens = &mailbox.FirebaseVerifier{ProjectID: p, TenantID: os.Getenv("FIREBASE_TENANT_ID")}
	} else if !s.DevAuth {
		return errors.New("FIREBASE_PROJECT_ID is required unless MAILBOX_DEV_AUTH=1")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	handler := s.Handler()
	if dir := os.Getenv("MAILBOX_WEB_DIR"); dir != "" {
		if os.Getenv("K_SERVICE") != "" {
			return errors.New("MAILBOX_WEB_DIR is for local runs; Firebase Hosting serves the app on GCP")
		}
		api := handler
		mux := http.NewServeMux()
		mux.Handle("/v1/", api)
		mux.Handle("/healthz", api)
		mux.Handle("/", http.FileServer(http.Dir(dir)))
		handler = mux
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
			name = "flow-remote"
		}
		return mailbox.OpenMongo(ctx, uri, name)
	default:
		return nil, fmt.Errorf("MAILBOX_STORE=%q: want memory or mongo", kind)
	}
}
