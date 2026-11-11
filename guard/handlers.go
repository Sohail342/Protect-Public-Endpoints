package guard

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"statelessprotection/internal/proto"
)

// Handler serves the handshake endpoints and client assets. Mount it at
// Config.PathPrefix, e.g. mux.Handle("/_sp/", g.Handler()).
func (g *Guard) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, g.cfg.PathPrefix)
		switch {
		case !ok:
			http.NotFound(w, r)
		case rest == "challenge" && r.Method == http.MethodGet:
			g.handleChallenge(w, r)
		case rest == "token" && r.Method == http.MethodPost:
			g.handleToken(w, r)
		case strings.HasPrefix(rest, "w/") && r.Method == http.MethodGet:
			g.handleAsset(w, r, strings.TrimPrefix(rest, "w/"))
		default:
			http.NotFound(w, r)
		}
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (g *Guard) note(r *http.Request, reason string) {
	if g.cfg.OnReject != nil {
		g.cfg.OnReject(r, reason)
	}
}

func (g *Guard) deny(w http.ResponseWriter, r *http.Request, reason string) {
	g.note(r, reason)
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
}

type challengeResp struct {
	C    string `json:"c"`    // MAC'd challenge, echoed back to /token
	Seed string `json:"seed"` // base64url
	Prog string `json:"prog"` // base64url epoch program for this variant
	WASM string `json:"wasm"` // variant URL
	Diff int    `json:"diff"` // PoW bits for the token
	WPow int    `json:"wpow"` // PoW bits to attach to write requests
	Now  int64  `json:"now"`  // server clock, unix ms
}

func (g *Guard) handleChallenge(w http.ResponseWriter, r *http.Request) {
	kid := g.cfg.ActiveKID
	ep := g.epoch()
	now := g.cfg.Now()
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	seedS := b64.EncodeToString(seed)
	c := g.mint(kid, claims{
		Typ:  "c",
		Ep:   ep,
		Seed: seedS,
		Exp:  now.Add(g.cfg.ChallengeTTL).UnixMilli(),
		Bind: g.bind(kid, r),
		Diff: g.cfg.ChallengePoWBits,
	})
	writeJSON(w, http.StatusOK, challengeResp{
		C:    c,
		Seed: seedS,
		Prog: b64.EncodeToString(g.program(kid, ep)),
		WASM: g.cfg.PathPrefix + "w/" + g.names[g.variantIndex(kid, ep)],
		Diff: g.cfg.ChallengePoWBits,
		WPow: g.cfg.WritePoWBits,
		Now:  now.UnixMilli(),
	})
}

type tokenReq struct {
	C     string `json:"c"`
	N     uint64 `json:"n"`     // PoW counter
	Env   uint32 `json:"env"`   // environment bits the client mixed into Ks
	Proof string `json:"proof"` // base64url HMAC(Ks, challenge)
}

func (g *Guard) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
		g.deny(w, r, "token: bad body")
		return
	}
	kid, c, err := g.parse(req.C, "c")
	if err != nil {
		g.deny(w, r, "token: challenge "+err.Error())
		return
	}
	now := g.cfg.Now()
	cur := g.epoch()
	switch {
	case now.UnixMilli() > c.Exp:
		g.deny(w, r, "token: challenge expired")
		return
	case c.Ep != cur && c.Ep != cur-1:
		g.deny(w, r, "token: stale epoch")
		return
	case c.Bind != g.bind(kid, r):
		g.deny(w, r, "token: binding mismatch")
		return
	case !proto.PowCheck([]byte(req.C), req.N, c.Diff):
		g.deny(w, r, "token: bad proof of work")
		return
	case g.cfg.EnvPolicy != nil && !g.cfg.EnvPolicy(req.Env):
		g.deny(w, r, "token: environment rejected")
		return
	}
	seed, err := b64.DecodeString(c.Seed)
	if err != nil {
		g.deny(w, r, "token: bad seed")
		return
	}
	proof, _ := b64.DecodeString(req.Proof)
	ks := g.sessionKey(kid, c.Ep, seed, req.Env)
	if !hmac.Equal(proof, proto.Proof(ks, req.C)) {
		g.deny(w, r, "token: wrong session key (program not executed correctly)")
		return
	}
	exp := now.Add(g.cfg.TokenTTL)
	tok := g.mint(kid, claims{Typ: "k", Ep: c.Ep, Seed: c.Seed, Env: req.Env, Exp: exp.UnixMilli(), Bind: c.Bind})
	writeJSON(w, http.StatusOK, map[string]any{"t": tok, "exp": exp.UnixMilli()})
}

// handleAsset serves files that cmd/spgen wrote to WASMDir.
func (g *Guard) handleAsset(w http.ResponseWriter, r *http.Request, name string) {
	if g.cfg.WASMDir == "" || name == "" || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	switch filepath.Ext(name) {
	case ".wasm":
		w.Header().Set("Content-Type", "application/wasm")
		// Revalidate: a rebuild with the same seed keeps the file name.
		w.Header().Set("Cache-Control", "no-cache")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
	default:
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(g.cfg.WASMDir, name))
}

// replayTTL is how long a one-time key must be remembered.
func (g *Guard) replayTTL() time.Duration { return 2*g.cfg.Skew + time.Second }
