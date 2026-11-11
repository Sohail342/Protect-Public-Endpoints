package guard

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"statelessprotection/internal/proto"
	"statelessprotection/internal/vm"
)

var b64 = base64.RawURLEncoding

// claims is the payload of both challenges (Typ "c") and tokens (Typ "k").
type claims struct {
	Typ  string `json:"t"`
	Ep   int64  `json:"e"`           // epoch the session key belongs to
	Seed string `json:"s"`           // base64url, 16 random bytes
	Env  uint32 `json:"v,omitempty"` // client environment bits (tokens only)
	Exp  int64  `json:"x"`           // unix milliseconds
	Bind string `json:"b"`           // client binding
	Diff int    `json:"d,omitempty"` // PoW bits (challenges only)
}

// mint produces "kid.payload.mac".
func (g *Guard) mint(kid string, c claims) string {
	raw, _ := json.Marshal(c)
	p := b64.EncodeToString(raw)
	m := proto.MAC(g.keys[kid].mac, []byte(kid), []byte("."), []byte(p))
	return kid + "." + p + "." + b64.EncodeToString(m)
}

func (g *Guard) parse(tok, typ string) (string, claims, error) {
	var c claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", c, errors.New("malformed")
	}
	ks, ok := g.keys[parts[0]]
	if !ok {
		return "", c, errors.New("unknown key id")
	}
	got, err := b64.DecodeString(parts[2])
	if err != nil {
		return "", c, errors.New("malformed mac")
	}
	want := proto.MAC(ks.mac, []byte(parts[0]), []byte("."), []byte(parts[1]))
	if !hmac.Equal(got, want) {
		return "", c, errors.New("bad mac")
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", c, errors.New("malformed payload")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", c, errors.New("malformed payload")
	}
	if c.Typ != typ {
		return "", c, errors.New("wrong type")
	}
	return parts[0], c, nil
}

func (g *Guard) epoch() int64 {
	return g.cfg.Now().UnixMilli() / g.cfg.EpochLen.Milliseconds()
}

func epBytes(ep int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ep))
	return b[:]
}

// variantIndex picks which WASM variant serves an epoch.
func (g *Guard) variantIndex(kid string, ep int64) int {
	m := proto.MAC(g.keys[kid].prog, []byte("sp/variant\n"), epBytes(ep))
	return int(binary.BigEndian.Uint32(m) % uint32(len(g.specs)))
}

// program returns the epoch's program, wire-encoded for its variant.
func (g *Guard) program(kid string, ep int64) []byte {
	key := progKey{kid, ep}
	g.mu.Lock()
	defer g.mu.Unlock()
	if p, ok := g.progs[key]; ok {
		return p
	}
	if len(g.progs) > 64 { // bounded, purely derived cache
		g.progs = map[progKey][]byte{}
	}
	ins := vm.GenProgram(proto.MAC(g.keys[kid].prog, []byte("sp/epoch\n"), epBytes(ep)), g.cfg.ProgramLen)
	p := g.specs[g.variantIndex(kid, ep)].Encode(ins)
	g.progs[key] = p
	return p
}

// sessionKey recomputes Ks exactly as the client's WASM derived it.
func (g *Guard) sessionKey(kid string, ep int64, seed []byte, env uint32) []byte {
	spec := &g.specs[g.variantIndex(kid, ep)]
	regs := proto.InitRegs(seed, env)
	spec.Run(&regs, g.program(kid, ep))
	return proto.FinalizeKey(spec.Salt[:], &regs, seed, env)
}

// bind ties a challenge/token to the caller's User-Agent (and network).
func (g *Guard) bind(kid string, r *http.Request) string {
	ipPart := ""
	if g.cfg.BindIP {
		ipPart = ipPrefix(g.clientIP(r))
	}
	m := proto.MAC(g.keys[kid].mac, []byte("sp/bind\n"), []byte(r.UserAgent()), []byte("\n"), []byte(ipPart))
	return hex.EncodeToString(m[:8])
}

func (g *Guard) clientIP(r *http.Request) string {
	if g.cfg.ClientIP != nil {
		return g.cfg.ClientIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ipPrefix(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	n := 64
	if a.Unmap().Is4() {
		a, n = a.Unmap(), 24
	}
	p, err := a.Prefix(n)
	if err != nil {
		return s
	}
	return p.String()
}
