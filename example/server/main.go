// Command server is a demo API protected by the guard package.
//
//	go run ./cmd/spgen -n 4 -out dist
//	go run ./example/server
//
// then open http://localhost:8080.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"statelessprotection/guard"
	"statelessprotection/internal/proto"
)

func main() {
	addr := flag.String("addr", "localhost:8080", "listen address")
	dist := flag.String("dist", "dist", "directory written by cmd/spgen")
	web := flag.String("web", "example/web", "static demo page directory")
	pool := flag.Int("n", 4, "pool size used with cmd/spgen")
	epoch := flag.Duration("epoch", 5*time.Minute, "program rotation period")
	ttl := flag.Duration("ttl", 10*time.Minute, "token lifetime")
	browserOnly := flag.Bool("browser-only", true, "refuse tokens to clients that do not look like a browser")
	decoy := flag.Bool("decoy", false, "answer rejected reads with fake data instead of 403")
	flag.Parse()

	master := secret("SP_MASTER_KEY", "sp-dev-master-key")
	poolSeed := secret("SP_POOL_SEED", "sp-dev-pool-seed")

	cfg := guard.Config{
		Keys:      map[string][]byte{"k1": master},
		ActiveKID: "k1",
		PoolSeed:  poolSeed,
		PoolSize:  *pool,
		WASMDir:   *dist,
		EpochLen:  *epoch,
		TokenTTL:  *ttl,
		Store:     guard.NewMemoryStore(),
		OnReject: func(r *http.Request, reason string) {
			log.Printf("REJECT %s %s: %s", r.Method, r.URL.Path, reason)
		},
	}
	if *browserOnly {
		cfg.EnvPolicy = func(env uint32) bool {
			return env&proto.EnvWindow != 0 && env&proto.EnvDocument != 0 && env&proto.EnvNode == 0
		}
	}
	g, err := guard.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	readPolicy := guard.Policy{Seal: true}
	if *decoy {
		readPolicy.Decoy = http.HandlerFunc(fakeRates)
	}

	mux := http.NewServeMux()
	mux.Handle("/_sp/", g.Handler())
	mux.Handle("GET /api/rates", g.Protect(readPolicy)(http.HandlerFunc(rates)))
	mux.Handle("POST /api/contact", g.Protect(guard.Policy{PoWBits: 12, OneTime: true})(http.HandlerFunc(contact)))
	mux.Handle("/", http.FileServer(http.Dir(*web)))

	log.Printf("demo on http://%s (epoch %s, token ttl %s, pool %d)", *addr, *epoch, *ttl, *pool)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// secret reads a hex secret from the environment, or falls back to a fixed
// development value that must never be used outside a demo.
func secret(env, devLabel string) []byte {
	if v := os.Getenv(env); v != "" {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) < 32 {
			log.Fatalf("%s must be hex and at least 32 bytes", env)
		}
		return b
	}
	log.Printf("WARNING: %s not set, using an insecure development value", env)
	s := sha256.Sum256([]byte(devLabel))
	return s[:]
}

type rate struct {
	Lane string  `json:"lane"`
	Mode string  `json:"mode"`
	USD  float64 `json:"usd"`
	Days int     `json:"days"`
}

func rates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]rate{
		{"Karachi → Dubai", "Sea", 840, 6},
		{"Karachi → Hamburg", "Sea", 2150, 24},
		{"Lahore → London", "Air", 3980, 3},
		{"Karachi → Singapore", "Sea", 1320, 14},
	})
}

func fakeRates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]rate{
		{"Karachi → Dubai", "Sea", 1111, 9},
		{"Karachi → Hamburg", "Sea", 2222, 31},
	})
}

func contact(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("contact form accepted: %s", body)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "received": len(body)})
}
