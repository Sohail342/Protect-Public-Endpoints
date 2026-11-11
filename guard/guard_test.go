package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"statelessprotection/internal/proto"
	"statelessprotection/internal/vm"
)

// env is a test server plus a movable clock.
type env struct {
	t    *testing.T
	g    *Guard
	srv  *httptest.Server
	mu   sync.Mutex
	now  time.Time
	seed []byte
}

func newEnv(t *testing.T, mut func(*Config)) *env {
	e := &env{t: t, now: time.Unix(1_800_000_000, 0), seed: bytes.Repeat([]byte{7}, 32)}
	cfg := Config{
		Keys:             map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)},
		ActiveKID:        "k1",
		PoolSeed:         e.seed,
		PoolSize:         3,
		ChallengePoWBits: 8,
		WritePoWBits:     8,
		Store:            NewMemoryStore(),
		Now: func() time.Time {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.now
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.g = g
	mux := http.NewServeMux()
	mux.Handle("/_sp/", g.Handler())
	mux.Handle("/read", g.Protect(Policy{Seal: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"secret":"data"}`)
	})))
	mux.Handle("/write", g.Protect(Policy{PoWBits: 8, OneTime: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	})))
	mux.Handle("/decoy", g.Protect(Policy{Seal: true, Decoy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "fake")
	})})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "real") })))
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

// session is a client that plays the protocol natively, the way the WASM does.
type session struct {
	e     *env
	ua    string
	token string
	ks    []byte
}

func (e *env) do(req *http.Request, ua string) (*http.Response, []byte) {
	req.Header.Set("User-Agent", ua)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func (e *env) challenge(ua string) challengeResp {
	req, _ := http.NewRequest("GET", e.srv.URL+"/_sp/challenge", nil)
	res, b := e.do(req, ua)
	if res.StatusCode != 200 {
		e.t.Fatalf("challenge: %d", res.StatusCode)
	}
	var ch challengeResp
	if err := json.Unmarshal(b, &ch); err != nil {
		e.t.Fatal(err)
	}
	return ch
}

// deriveKs runs prog the way the named WASM variant would.
func (e *env) deriveKs(ch challengeResp, prog []byte, envBits uint32) []byte {
	for i := 0; i < 3; i++ {
		if strings.HasSuffix(ch.WASM, vm.Name(e.seed, i)+".wasm") {
			spec := vm.DeriveSpec(e.seed, i)
			seed, _ := b64.DecodeString(ch.Seed)
			regs := proto.InitRegs(seed, envBits)
			spec.Run(&regs, prog)
			return proto.FinalizeKey(spec.Salt[:], &regs, seed, envBits)
		}
	}
	e.t.Fatal("unknown variant " + ch.WASM)
	return nil
}

func (e *env) redeem(ch challengeResp, ks []byte, envBits uint32, ua string) (int, string) {
	body, _ := json.Marshal(tokenReq{
		C:     ch.C,
		N:     proto.PowSolve([]byte(ch.C), ch.Diff),
		Env:   envBits,
		Proof: b64.EncodeToString(proto.Proof(ks, ch.C)),
	})
	req, _ := http.NewRequest("POST", e.srv.URL+"/_sp/token", bytes.NewReader(body))
	res, b := e.do(req, ua)
	var out struct{ T string }
	json.Unmarshal(b, &out)
	return res.StatusCode, out.T
}

func (e *env) login(ua string) *session {
	ch := e.challenge(ua)
	prog, _ := b64.DecodeString(ch.Prog)
	ks := e.deriveKs(ch, prog, 3)
	code, tok := e.redeem(ch, ks, 3, ua)
	if code != 200 || tok == "" {
		e.t.Fatalf("token: %d", code)
	}
	return &session{e: e, ua: ua, token: tok, ks: ks}
}

// build signs a request; the caller may tamper with it before sending.
func (s *session) build(method, pathQuery string, body []byte, powBits int) *http.Request {
	req, _ := http.NewRequest(method, s.e.srv.URL+pathQuery, bytes.NewReader(body))
	ts := strconv.FormatInt(s.e.clock().UnixMilli(), 10)
	nonce := strings.Repeat("ab", 12)
	sig := b64.EncodeToString(proto.RequestSig(s.ks, method, req.URL.EscapedPath(), req.URL.RawQuery, body, ts, nonce))
	req.Header.Set(proto.HdrToken, s.token)
	req.Header.Set(proto.HdrTs, ts)
	req.Header.Set(proto.HdrNonce, nonce)
	req.Header.Set(proto.HdrSig, sig)
	if powBits > 0 {
		req.Header.Set(proto.HdrPow, strconv.FormatUint(proto.PowSolve([]byte(sig), powBits), 10))
	}
	return req
}

func clone(r *http.Request, body []byte) *http.Request {
	c, _ := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(body))
	c.Header = r.Header.Clone()
	return c
}

func TestSealedReadRoundTrip(t *testing.T) {
	e := newEnv(t, nil)
	s := e.login("browser/1")
	req := s.build("GET", "/read?q=1", nil, 0)
	res, body := e.do(req, s.ua)
	if res.StatusCode != 200 || res.Header.Get(proto.HdrSealed) != "1" {
		t.Fatalf("status %d sealed %q", res.StatusCode, res.Header.Get(proto.HdrSealed))
	}
	if bytes.Contains(body, []byte("secret")) {
		t.Fatal("plaintext leaked on the wire")
	}
	plain, err := proto.Open(s.ks, []byte(req.Header.Get(proto.HdrNonce)), body)
	if err != nil || string(plain) != `{"secret":"data"}` {
		t.Fatalf("unseal: %v %q", err, plain)
	}
	if res.Header.Get(proto.HdrCT) != "application/json" {
		t.Fatalf("content type not carried: %q", res.Header.Get(proto.HdrCT))
	}
}

func TestRejections(t *testing.T) {
	e := newEnv(t, nil)
	s := e.login("browser/1")

	status := func(req *http.Request, ua string) int {
		res, _ := e.do(req, ua)
		return res.StatusCode
	}
	plain, _ := http.NewRequest("GET", e.srv.URL+"/read", nil)
	if c := status(plain, s.ua); c != 403 {
		t.Errorf("no headers: got %d", c)
	}
	if c := status(s.build("GET", "/read", nil, 0), "other-agent/9"); c != 403 {
		t.Errorf("token on another client: got %d", c)
	}
	moved := s.build("GET", "/read", nil, 0)
	moved.URL.RawQuery = "page=2"
	if c := status(moved, s.ua); c != 403 {
		t.Errorf("signature reused for another URL: got %d", c)
	}
	bad := s.build("GET", "/read", nil, 0)
	tok := []byte(s.token)
	tok[len(tok)-1] ^= 1
	bad.Header.Set(proto.HdrToken, string(tok))
	if c := status(bad, s.ua); c != 403 {
		t.Errorf("tampered token: got %d", c)
	}
	if c := status(s.build("POST", "/write", []byte("x"), 0), s.ua); c != 403 {
		t.Errorf("write without proof of work: got %d", c)
	}
	swapped := s.build("POST", "/write", []byte("original"), 8)
	if c := status(clone(swapped, []byte("tampered")), s.ua); c != 403 {
		t.Errorf("body swapped under a valid signature: got %d", c)
	}

	// replay: fine once, refused twice (nonce store), refused when stale.
	w := s.build("POST", "/write", []byte("hello"), 8)
	if c := status(clone(w, []byte("hello")), s.ua); c != 200 {
		t.Fatalf("legit write: got %d", c)
	}
	if c := status(clone(w, []byte("hello")), s.ua); c != 403 {
		t.Errorf("immediate replay: got %d", c)
	}
	r := s.build("GET", "/read", nil, 0)
	e.advance(31 * time.Second)
	if c := status(r, s.ua); c != 403 {
		t.Errorf("replay after the timestamp window: got %d", c)
	}
	e.advance(10 * time.Minute)
	if c := status(s.build("GET", "/read", nil, 0), s.ua); c != 403 {
		t.Errorf("expired token: got %d", c)
	}
}

func TestProgramRotates(t *testing.T) {
	e := newEnv(t, nil)
	ua := "browser/1"
	old := e.challenge(ua)
	oldProg, _ := b64.DecodeString(old.Prog)

	e.advance(5 * time.Minute) // next epoch
	ch := e.challenge(ua)
	newProg, _ := b64.DecodeString(ch.Prog)
	if bytes.Equal(oldProg, newProg) {
		t.Fatal("program did not change with the epoch")
	}
	// A scraper that hard-coded last epoch's program derives the wrong key.
	if code, _ := e.redeem(ch, e.deriveKs(ch, oldProg, 3), 3, ua); code != 403 {
		t.Errorf("stale program accepted: %d", code)
	}
	if code, _ := e.redeem(ch, e.deriveKs(ch, newProg, 3), 3, ua); code != 200 {
		t.Errorf("current program refused: %d", code)
	}
	// An old challenge cannot be redeemed after its lifetime.
	if code, _ := e.redeem(old, e.deriveKs(old, oldProg, 3), 3, ua); code != 403 {
		t.Errorf("expired challenge accepted: %d", code)
	}
}

func TestEnvPolicyAndDecoy(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.EnvPolicy = func(env uint32) bool { return env&proto.EnvDocument != 0 }
	})
	ch := e.challenge("node")
	prog, _ := b64.DecodeString(ch.Prog)
	if code, _ := e.redeem(ch, e.deriveKs(ch, prog, proto.EnvNode), proto.EnvNode, "node"); code != 403 {
		t.Errorf("non-browser environment got a token: %d", code)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/decoy", nil)
	res, body := e.do(req, "curl")
	if res.StatusCode != 200 || string(body) != "fake" {
		t.Errorf("decoy: %d %q", res.StatusCode, body)
	}
}

func TestKeyRotation(t *testing.T) {
	e := newEnv(t, nil)
	s := e.login("browser/1")
	// Same deployment after rotating: k2 is active, k1 is still accepted.
	cfg := e.g.cfg
	cfg.Keys = map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32), "k2": bytes.Repeat([]byte{2}, 32)}
	cfg.ActiveKID = "k2"
	g2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := g2.Protect(Policy{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := s.build("GET", "/read", nil, 0)
	req.Header.Set("User-Agent", s.ua)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("token minted under the previous key refused: %d", rec.Code)
	}
}
