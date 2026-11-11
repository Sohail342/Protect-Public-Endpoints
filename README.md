# Stateless Protection

Go middleware plus a browser WASM client that protects public endpoints
against scraping, form abuse and API replay without server-side sessions.
Design, threat model and limits: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Run the demo

```bash
go run ./cmd/spgen -n 4 -out dist
```

```bash
go run ./example/server -epoch 30s -ttl 60s
```

### Smaller build with TinyGo (recommended)

TinyGo produces 141 KB variants instead of 2.5 MB. It needs `tinygo` on
`PATH` and, on Windows, `WASMOPT` pointing at Binaryen's `wasm-opt.exe`.
On this machine both live under `C:\Users\Admin\.tinygo` (PowerShell):

```powershell
$env:PATH = "C:\Users\Admin\.tinygo\0.44.0\bin;$env:PATH"
$env:WASMOPT = "C:\Users\Admin\.tinygo\binaryen-dl\binaryen-version_133\bin\wasm-opt.exe"
$env:GOCACHE = "C:\Users\Admin\.tinygo\cache"
go run ./cmd/spgen -n 4 -out dist-tinygo -compiler tinygo
```

Then start the server with `-dist dist-tinygo`.

Open http://localhost:8080, then try the attacker script:

```bash
node example/attacker/attack.mjs http://localhost:8080 dist
```

## Test

```bash
go test ./...
```

The `e2e` test builds real WASM variants and drives them with Node; add
`-short` to skip it.

## Layout

| Path | Purpose |
|---|---|
| `guard/` | The importable package: config, tokens, middleware, replay store |
| `internal/proto/` | Signing, proof-of-work and sealing rules shared by server and client |
| `internal/vm/` | Epoch program generator, variant specs, server-side interpreter |
| `cmd/spgen/` | Builds the pool of WASM variants |
| `client/wasm/`, `client/js/` | Browser client (`variant_gen.go` is generated) |
| `example/` | Demo server, page and attacker script |

For real use set `SP_MASTER_KEY` and `SP_POOL_SEED` (hex, 32+ bytes); the
defaults are public development values.
