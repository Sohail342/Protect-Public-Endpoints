// Package guard protects public HTTP endpoints without server-side sessions.
//
// Everything the server needs to verify a request is recomputed from a master
// secret plus what the client sends: a MAC'd token, a request signature made
// with a session key the client had to derive by running that epoch's
// program inside a WASM variant, and (for writes) a proof-of-work stamp.
// See docs/ARCHITECTURE.md.
package guard

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"statelessprotection/internal/proto"
	"statelessprotection/internal/vm"
)

// Config configures a Guard. Zero values get safe defaults.
type Config struct {
	// Keys maps key id -> master secret (>= 32 bytes). Keep old ids here
	// while rotating so outstanding tokens stay valid; mint with ActiveKID.
	Keys      map[string][]byte
	ActiveKID string

	// PoolSeed and PoolSize must match what cmd/spgen built into WASMDir.
	PoolSeed []byte
	PoolSize int
	WASMDir  string

	EpochLen     time.Duration // program rotation period (default 5m)
	TokenTTL     time.Duration // default 10m
	ChallengeTTL time.Duration // default 2m
	Skew         time.Duration // allowed request timestamp drift (default 30s)

	ChallengePoWBits int // work to obtain a token (default 16)
	WritePoWBits     int // work clients attach to non-GET requests (default 12)
	ProgramLen       int // instructions per epoch program (default 64)

	// BindIP additionally binds tokens to the client's /24 (IPv4) or /64.
	BindIP   bool
	ClientIP func(*http.Request) string // default: RemoteAddr

	// EnvPolicy decides whether the client-reported environment bits
	// (proto.Env*) may receive a token. nil accepts everything.
	EnvPolicy func(env uint32) bool

	// Store enables strict one-time use for Policy.OneTime routes. Optional:
	// this is the only piece of server-side state.
	Store NonceStore

	MaxBody    int64  // default 1 MiB
	PathPrefix string // default "/_sp/"

	// OnReject is told why a request was refused. The client never is.
	OnReject func(r *http.Request, reason string)

	Now func() time.Time // for tests
}

// Policy is the protection applied to one route.
type Policy struct {
	Seal    bool // encrypt the response body under the session key
	PoWBits int  // required per-request proof of work (<= Config.WritePoWBits)
	OneTime bool // reject a repeated request (needs Config.Store)

	// Decoy, if set, answers rejected requests instead of a 403, so a
	// scraper does not notice that it is being fed fake data.
	Decoy http.Handler
}

type keyset struct{ mac, prog []byte }

// Guard is safe for concurrent use and holds no per-client state.
type Guard struct {
	cfg   Config
	keys  map[string]keyset
	specs []vm.Spec
	names []string

	mu    sync.Mutex
	progs map[progKey][]byte // derived cache, recomputable at any time
}

type progKey struct {
	kid string
	ep  int64
}

var kidRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// New validates cfg and builds a Guard.
func New(cfg Config) (*Guard, error) {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.EpochLen, 5*time.Minute)
	def(&cfg.TokenTTL, 10*time.Minute)
	def(&cfg.ChallengeTTL, 2*time.Minute)
	def(&cfg.Skew, 30*time.Second)
	if cfg.ChallengePoWBits == 0 {
		cfg.ChallengePoWBits = 16
	}
	if cfg.WritePoWBits == 0 {
		cfg.WritePoWBits = 12
	}
	if cfg.ProgramLen == 0 {
		cfg.ProgramLen = 64
	}
	if cfg.MaxBody == 0 {
		cfg.MaxBody = 1 << 20
	}
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = "/_sp/"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	if _, ok := cfg.Keys[cfg.ActiveKID]; !ok {
		return nil, errors.New("guard: ActiveKID not present in Keys")
	}
	g := &Guard{cfg: cfg, keys: map[string]keyset{}, progs: map[progKey][]byte{}}
	for kid, k := range cfg.Keys {
		if !kidRE.MatchString(kid) {
			return nil, fmt.Errorf("guard: invalid key id %q", kid)
		}
		if len(k) < 32 {
			return nil, fmt.Errorf("guard: key %q is shorter than 32 bytes", kid)
		}
		g.keys[kid] = keyset{
			mac:  proto.MAC(k, []byte("sp/k/mac")),
			prog: proto.MAC(k, []byte("sp/k/prog")),
		}
	}
	if len(cfg.PoolSeed) < 16 || cfg.PoolSize < 1 {
		return nil, errors.New("guard: PoolSeed (>=16 bytes) and PoolSize (>=1) are required")
	}
	for i := 0; i < cfg.PoolSize; i++ {
		g.specs = append(g.specs, vm.DeriveSpec(cfg.PoolSeed, i))
		name := vm.Name(cfg.PoolSeed, i) + ".wasm"
		g.names = append(g.names, name)
		if cfg.WASMDir != "" {
			if _, err := os.Stat(filepath.Join(cfg.WASMDir, name)); err != nil {
				return nil, fmt.Errorf("guard: variant %d missing in WASMDir (run cmd/spgen with the same seed and -n): %w", i, err)
			}
		}
	}
	return g, nil
}
