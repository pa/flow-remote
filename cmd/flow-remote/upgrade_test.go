package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeGitHub serves one release, v9.9.9, the way GitHub's API does.
func fakeGitHub(t *testing.T, bin []byte, tamper bool) {
	t.Helper()
	tag := "v9.9.9"
	name := fmt.Sprintf("flow-remote_%s_%s_%s.tar.gz", tag, runtime.GOOS, runtime.GOARCH)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	dir := strings.TrimSuffix(name, ".tar.gz")
	tw.WriteHeader(&tar.Header{Name: dir + "/README.md", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("hi"))
	tw.WriteHeader(&tar.Header{Name: dir + "/flow-remote", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	tw.Write(bin)
	tw.Close()
	zw.Close()
	tgz := buf.Bytes()
	sum := sha256.Sum256(tgz)
	if tamper {
		sum[0] ^= 1
	}
	sums := hex.EncodeToString(sum[:]) + "  " + name + "\n"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			json.NewEncoder(w).Encode(release{Tag: tag, Assets: []asset{
				{Name: name, URL: srv.URL + "/asset/tgz"}, {Name: "checksums.txt", URL: srv.URL + "/asset/sums"},
			}})
		case "/asset/tgz":
			w.Write(tgz)
		case "/asset/sums":
			io.WriteString(w, sums)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := releasesAPI
	releasesAPI = srv.URL
	t.Cleanup(func() { releasesAPI = old })
	t.Setenv("GH_TOKEN", "test") // don't ask the real gh
}

func TestUpgradeReplacesTheBinary(t *testing.T) {
	fakeGitHub(t, []byte("new binary"), false)
	exe := filepath.Join(t.TempDir(), "flow-remote")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	var out bytes.Buffer
	ok, err := upgradeTo(context.Background(), exe, false, &out)
	if err != nil || !ok {
		t.Fatalf("upgrade: %v %v", ok, err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("binary is %q", b)
	}
	if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestUpgradeRefusesABadChecksum(t *testing.T) {
	fakeGitHub(t, []byte("new binary"), true)
	exe := filepath.Join(t.TempDir(), "flow-remote")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	if _, err := upgradeTo(context.Background(), exe, false, io.Discard); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old binary" {
		t.Fatal("a bad download replaced the binary")
	}
}

func TestUpgradeCheckAndUpToDate(t *testing.T) {
	fakeGitHub(t, []byte("new binary"), false)
	exe := filepath.Join(t.TempDir(), "flow-remote")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	var out bytes.Buffer
	if ok, err := upgradeTo(context.Background(), exe, true, &out); ok || err != nil || !strings.Contains(out.String(), "v9.9.9 is available") {
		t.Fatalf("--check: %v %v %q", ok, err, out.String())
	}
	old := version
	version = "v9.9.9"
	defer func() { version = old }()
	out.Reset()
	if ok, _ := upgradeTo(context.Background(), exe, false, &out); ok || !strings.Contains(out.String(), "latest release") {
		t.Fatalf("up to date: %v %q", ok, out.String())
	}
}
