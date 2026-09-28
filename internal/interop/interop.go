// Package interop runs web/js under Node so Go tests can check that the
// phone's WebCrypto code and the Mac's Go code agree on every byte.
package interop

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Node sends req to driver.mjs and decodes its answer into resp. It skips
// the test when node isn't installed.
func Node(t testing.TB, req, resp any) {
	t.Helper()
	bin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; WebCrypto interop not checked")
	}
	_, here, _, _ := runtime.Caller(0)
	in, _ := json.Marshal(req)
	cmd := exec.Command(bin, filepath.Join(filepath.Dir(here), "driver.mjs"))
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	if err := json.Unmarshal(out, resp); err != nil {
		t.Fatalf("node output %q: %v", out, err)
	}
}
