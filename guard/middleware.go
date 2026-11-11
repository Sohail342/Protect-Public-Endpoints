package guard

import (
	"bytes"
	"crypto/hmac"
	"io"
	"net/http"
	"strconv"

	"statelessprotection/internal/proto"
)

// Protect wraps a handler so it only runs for requests that carry a valid
// token, a fresh signature made with the session key, and whatever else the
// policy asks for.
func (g *Guard) Protect(p Policy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ks, nonce, reason := g.verify(r, p)
			if reason != "" {
				g.note(r, reason)
				if p.Decoy != nil {
					p.Decoy.ServeHTTP(w, r)
					return
				}
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
			if !p.Seal {
				next.ServeHTTP(w, r)
				return
			}
			rec := &capture{hdr: http.Header{}}
			next.ServeHTTP(rec, r)
			sealed, err := proto.Seal(ks, []byte(nonce), rec.buf.Bytes())
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			h := w.Header()
			for k, v := range rec.hdr {
				h[k] = v
			}
			h.Set(proto.HdrCT, rec.hdr.Get("Content-Type"))
			h.Set(proto.HdrSealed, "1")
			h.Set("Content-Type", "application/octet-stream")
			h.Set("Content-Length", strconv.Itoa(len(sealed)))
			h.Set("Cache-Control", "no-store")
			h.Del("Content-Encoding")
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			w.WriteHeader(rec.status)
			w.Write(sealed)
		})
	}
}

// verify returns the session key and request nonce, or a rejection reason.
func (g *Guard) verify(r *http.Request, p Policy) (ks []byte, nonce, reason string) {
	tok := r.Header.Get(proto.HdrToken)
	ts := r.Header.Get(proto.HdrTs)
	nonce = r.Header.Get(proto.HdrNonce)
	sig := r.Header.Get(proto.HdrSig)
	if tok == "" || ts == "" || nonce == "" || sig == "" {
		return nil, "", "missing protection headers"
	}
	kid, c, err := g.parse(tok, "k")
	if err != nil {
		return nil, "", "token " + err.Error()
	}
	now := g.cfg.Now().UnixMilli()
	if now > c.Exp {
		return nil, "", "token expired"
	}
	if c.Bind != g.bind(kid, r) {
		return nil, "", "token used by a different client"
	}
	tsv, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, "", "bad timestamp"
	}
	if d := now - tsv; d > g.cfg.Skew.Milliseconds() || d < -g.cfg.Skew.Milliseconds() {
		return nil, "", "stale timestamp"
	}
	if len(nonce) != 24 {
		return nil, "", "bad nonce"
	}

	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, g.cfg.MaxBody+1))
		if err != nil || int64(len(body)) > g.cfg.MaxBody {
			return nil, "", "body unreadable or too large"
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	seed, err := b64.DecodeString(c.Seed)
	if err != nil {
		return nil, "", "bad seed"
	}
	ks = g.sessionKey(kid, c.Ep, seed, c.Env)
	got, err := b64.DecodeString(sig)
	want := proto.RequestSig(ks, r.Method, r.URL.EscapedPath(), r.URL.RawQuery, body, ts, nonce)
	if err != nil || !hmac.Equal(got, want) {
		return nil, "", "bad signature"
	}

	if p.PoWBits > 0 {
		n, err := strconv.ParseUint(r.Header.Get(proto.HdrPow), 10, 64)
		if err != nil || !proto.PowCheck([]byte(sig), n, p.PoWBits) {
			return nil, "", "missing or insufficient proof of work"
		}
	}
	if p.OneTime && g.cfg.Store != nil && g.cfg.Store.Seen(sig, g.replayTTL()) {
		return nil, "", "replayed request"
	}
	return ks, nonce, ""
}

// capture buffers a handler's response so it can be sealed.
type capture struct {
	hdr    http.Header
	status int
	buf    bytes.Buffer
}

func (c *capture) Header() http.Header { return c.hdr }

func (c *capture) WriteHeader(s int) {
	if c.status == 0 {
		c.status = s
	}
}

func (c *capture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.buf.Write(b)
}
