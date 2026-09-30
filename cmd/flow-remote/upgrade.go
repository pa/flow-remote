package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// releasesAPI is GitHub's API for this repository's releases; tests point
// it at a local server.
var releasesAPI = "https://api.github.com/repos/pa/flow-remote/releases"

type release struct {
	Tag    string  `json:"tag_name"`
	Assets []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"url"` // the API URL; with Accept: octet-stream it serves the file
}

// githubToken is for a private repository: GH_TOKEN or GITHUB_TOKEN, else
// the GitHub CLI's login. A public repository needs none.
func githubToken() string {
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if gh, err := exec.LookPath("gh"); err == nil {
		if out, err := exec.Command(gh, "auth", "token").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func githubGet(ctx context.Context, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok := githubToken(); tok != "" {
		// Go drops this header when GitHub redirects the download to its
		// storage host, so the token only goes to GitHub.
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 200<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, errors.New("no release found (a private repository needs `gh auth login` or GH_TOKEN)")
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s", res.Status)
	}
	return body, nil
}

// checksumFor finds name's SHA-256 in a sha256sum-style checksums.txt.
func checksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

// binaryFrom pulls the flow-remote executable out of a release tarball.
func binaryFrom(tgz []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the release archive has no flow-remote binary")
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == "flow-remote" {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
}

// replaceExecutable swaps exe for data in one rename, so a crash midway
// leaves the old binary, not half of the new one.
func replaceExecutable(exe string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".flow-remote-upgrade-*")
	if err != nil {
		return fmt.Errorf("can't write next to %s (%w); reinstall with install.sh instead", exe, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), exe)
}

func upgrade(ctx context.Context, args []string) error {
	check := len(args) > 0 && args[0] == "--check"
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	upgraded, err := upgradeTo(ctx, exe, check, os.Stdout)
	if err != nil || !upgraded {
		return err
	}
	// A running background service keeps the old binary until it restarts.
	if exec.Command("launchctl", "print", domain()+"/"+agentLabel()).Run() == nil {
		if err := exec.Command("launchctl", "kickstart", "-k", domain()+"/"+agentLabel()).Run(); err != nil {
			fmt.Println("restart it to use the new version: `flow-remote stop && flow-remote start`.")
		} else {
			fmt.Println("restarted the background service on the new version.")
		}
	}
	return nil
}

// upgradeTo installs the latest release over exe if it's newer than this
// build, and reports whether it did.
func upgradeTo(ctx context.Context, exe string, check bool, out io.Writer) (bool, error) {
	rel, err := latestRelease(ctx)
	if err != nil {
		return false, err
	}
	if rel.Tag == version {
		fmt.Fprintf(out, "flow-remote %s is the latest release.\n", version)
		return false, nil
	}
	if check {
		fmt.Fprintf(out, "flow-remote %s is available (this is %s). Run `flow-remote upgrade`.\n", rel.Tag, version)
		return false, nil
	}
	name := fmt.Sprintf("flow-remote_%s_%s_%s.tar.gz", rel.Tag, runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(out, "downloading %s...\n", name)
	tgz, err := downloadVerified(ctx, rel, name)
	if err != nil {
		return false, err
	}
	bin, err := binaryFrom(tgz)
	if err != nil {
		return false, err
	}
	if err := replaceExecutable(exe, bin); err != nil {
		return false, err
	}
	fmt.Fprintf(out, "upgraded %s from %s to %s.\n", exe, version, rel.Tag)
	return true, nil
}

// latestRelease looks up the newest published release.
func latestRelease(ctx context.Context) (release, error) {
	var rel release
	body, err := githubGet(ctx, releasesAPI+"/latest", "application/vnd.github+json")
	if err != nil {
		return rel, fmt.Errorf("looking up the latest release: %w", err)
	}
	if err := json.Unmarshal(body, &rel); err != nil || rel.Tag == "" {
		return rel, fmt.Errorf("reading the latest release: %v", err)
	}
	return rel, nil
}

// downloadVerified downloads the release asset called name and returns it
// only if it matches its line in the release's checksums.txt.
func downloadVerified(ctx context.Context, rel release, name string) ([]byte, error) {
	var tarURL, sumsURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case name:
			tarURL = a.URL
		case "checksums.txt":
			sumsURL = a.URL
		}
	}
	if tarURL == "" || sumsURL == "" {
		return nil, fmt.Errorf("release %s has no %s (or no checksums.txt)", rel.Tag, name)
	}
	tgz, err := githubGet(ctx, tarURL, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	sums, err := githubGet(ctx, sumsURL, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	want, err := checksumFor(sums, name)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(tgz)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("%s doesn't match its checksum; not installing it", name)
	}
	return tgz, nil
}
