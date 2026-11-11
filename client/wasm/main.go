//go:build js && wasm

// Command wasm is the browser half of the protection. It is built once per
// variant by cmd/spgen, which generates variant_gen.go (runProgram and
// variantSalt) next to this file. It only uses syscall/js and std crypto so
// it builds with both the standard Go compiler and TinyGo (-target wasm).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"syscall/js"

	"statelessprotection/internal/proto"
)

var (
	b64      = base64.RawURLEncoding
	ks       []byte  // session key; never handed to JavaScript
	offsetMs float64 // server clock minus local clock
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("handshake", js.FuncOf(handshake))
	api.Set("sign", js.FuncOf(sign))
	api.Set("unseal", js.FuncOf(unseal))
	js.Global().Call("__sp_boot", api)
	select {}
}

func truthy(v js.Value) bool { return v.Truthy() }

// probeEnv reports what kind of host is running this module. The bits are
// mixed into the session key, so lying about them requires knowing to.
func probeEnv() uint32 {
	g := js.Global()
	var env uint32
	if truthy(g.Get("window")) {
		env |= proto.EnvWindow
	}
	if d := g.Get("document"); truthy(d) && d.Get("createElement").Type() == js.TypeFunction {
		env |= proto.EnvDocument
	}
	if n := g.Get("navigator"); truthy(n) && n.Get("webdriver").Type() == js.TypeBoolean && n.Get("webdriver").Bool() {
		env |= proto.EnvWebdriver
	}
	if p := g.Get("process"); truthy(p) && truthy(p.Get("versions")) && truthy(p.Get("versions").Get("node")) {
		env |= proto.EnvNode
	}
	return env
}

func nowMs() float64 { return js.Global().Get("Date").Call("now").Float() }

// handshake(challenge, seedB64, progB64, powBits, serverNowMs) -> {n, env, proof}
func handshake(_ js.Value, a []js.Value) any {
	c := a[0].String()
	seed, err1 := b64.DecodeString(a[1].String())
	prog, err2 := b64.DecodeString(a[2].String())
	if err1 != nil || err2 != nil {
		return js.Null()
	}
	offsetMs = a[4].Float() - nowMs()

	env := probeEnv()
	regs := proto.InitRegs(seed, env)
	runProgram(&regs, prog)
	ks = proto.FinalizeKey(variantSalt[:], &regs, seed, env)

	out := js.Global().Get("Object").New()
	out.Set("n", float64(proto.PowSolve([]byte(c), a[3].Int())))
	out.Set("env", int(env))
	out.Set("proof", b64.EncodeToString(proto.Proof(ks, c)))
	return out
}

func bytesArg(v js.Value) []byte {
	if !v.Truthy() {
		return nil
	}
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

// sign(method, path, query, bodyUint8Array, powBits) -> {ts, nonce, sig, pow}
func sign(_ js.Value, a []js.Value) any {
	if ks == nil {
		return js.Null()
	}
	var nb [12]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return js.Null()
	}
	ts := strconv.FormatInt(int64(nowMs()+offsetMs), 10)
	nonce := hex.EncodeToString(nb[:])
	sig := b64.EncodeToString(proto.RequestSig(ks, a[0].String(), a[1].String(), a[2].String(), bytesArg(a[3]), ts, nonce))

	out := js.Global().Get("Object").New()
	out.Set("ts", ts)
	out.Set("nonce", nonce)
	out.Set("sig", sig)
	if bits := a[4].Int(); bits > 0 {
		out.Set("pow", strconv.FormatUint(proto.PowSolve([]byte(sig), bits), 10))
	}
	return out
}

// unseal(sealedUint8Array, nonce) -> Uint8Array | null
func unseal(_ js.Value, a []js.Value) any {
	if ks == nil {
		return js.Null()
	}
	plain, err := proto.Open(ks, []byte(a[1].String()), bytesArg(a[0]))
	if err != nil {
		return js.Null()
	}
	out := js.Global().Get("Uint8Array").New(len(plain))
	js.CopyBytesToJS(out, plain)
	return out
}
