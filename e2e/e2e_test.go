// Package e2e builds a real WASM pool and drives it with Node, checking that
// every generated variant derives the same session key as the server's
// interpreter (if it did not, the handshake proof would be refused).
package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"statelessprotection/guard"
)

func TestEveryVariantAgainstServer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds WASM; skipped in -short")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	const pool = 3
	seed := bytes.Repeat([]byte{0x5e}, 32)
	dist := t.TempDir()

	compiler := os.Getenv("SP_E2E_COMPILER") // "go" (default) or "tinygo"
	if compiler == "" {
		compiler = "go"
	}
	gen := exec.Command("go", "run", "./cmd/spgen", "-n", "3", "-out", dist, "-seed", hex.EncodeToString(seed), "-compiler", compiler)
	gen.Dir = root
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("spgen: %v\n%s", err, out)
	} else {
		t.Logf("\n%s", out)
	}

	var epochShift atomic.Int64
	var rejects sync.Map
	g, err := guard.New(guard.Config{
		Keys:      map[string][]byte{"k1": bytes.Repeat([]byte{9}, 32)},
		ActiveKID: "k1",
		PoolSeed:  seed,
		PoolSize:  pool,
		WASMDir:   dist,
		Store:     guard.NewMemoryStore(),
		Now:       func() time.Time { return time.Now().Add(time.Duration(epochShift.Load()) * 5 * time.Minute) },
		OnReject:  func(r *http.Request, reason string) { rejects.Store(reason, true) },
	})
	if err != nil {
		t.Fatal(err)
	}

	var seen sync.Map // variant file -> true
	mux := http.NewServeMux()
	sp := g.Handler()
	mux.HandleFunc("/_sp/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			seen.Store(filepath.Base(r.URL.Path), true)
		}
		sp.ServeHTTP(w, r)
	})
	mux.Handle("GET /api/data", g.Protect(guard.Policy{Seal: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"x":"`+r.URL.Query().Get("x")+`"}`)
	})))
	mux.Handle("POST /api/form", g.Protect(guard.Policy{PoWBits: 12, OneTime: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	count := func() (n int) {
		seen.Range(func(_, _ any) bool { n++; return true })
		return
	}
	for i := 0; i < 40 && count() < pool; i++ {
		epochShift.Store(int64(i))
		cmd := exec.Command("node", filepath.Join(root, "e2e", "client.mjs"), srv.URL, dist)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			rejects.Range(func(k, _ any) bool { t.Logf("server rejected: %v", k); return true })
			t.Fatalf("client failed at epoch shift %d: %v\n%s\n%s", i, err, out, stderr.String())
		}
		var res struct {
			S1, S2                   int
			Data                     map[string]string
			Form                     string
			FirstMs, WriteMs, ReadMs int
		}
		if err := json.Unmarshal(bytes.TrimSpace(out), &res); err != nil {
			t.Fatalf("bad client output %q: %v", out, err)
		}
		if res.S1 != 200 || res.Data["x"] != "1" || res.S2 != 200 || res.Form != `{"hello":"world"}` {
			t.Fatalf("wrong result at epoch shift %d: %s", i, out)
		}
		t.Logf("epoch shift %d ok: first sealed read incl. handshake %d ms, write %d ms, read %d ms",
			i, res.FirstMs, res.WriteMs, res.ReadMs)
	}
	if count() < pool {
		t.Fatalf("only %d of %d variants were exercised", count(), pool)
	}
	if fi, err := os.Stat(filepath.Join(dist, "sp.js")); err != nil || fi.Size() == 0 {
		t.Fatal("sp.js not copied to dist")
	}
}
