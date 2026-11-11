// Package proto holds the wire-level rules shared by the server (guard) and
// the browser client (client/wasm): header names, key derivation, request
// signing, proof-of-work and response sealing. It only uses the standard
// library and is safe to compile to WebAssembly.
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
)

const (
	HdrToken  = "X-SP-Token"
	HdrTs     = "X-SP-Ts"
	HdrNonce  = "X-SP-Nonce"
	HdrSig    = "X-SP-Sig"
	HdrPow    = "X-SP-Pow"
	HdrSealed = "X-SP-Sealed"
	HdrCT     = "X-SP-Content-Type"
)

// Environment bits reported by the client and mixed into the session key.
const (
	EnvWindow    uint32 = 1 << 0
	EnvDocument  uint32 = 1 << 1
	EnvWebdriver uint32 = 1 << 2
	EnvNode      uint32 = 1 << 3
)

// MAC is HMAC-SHA256 over the concatenation of parts.
func MAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// InitRegs turns the challenge seed and environment bits into the VM's
// starting registers.
func InitRegs(seed []byte, env uint32) [8]uint32 {
	var e [4]byte
	binary.LittleEndian.PutUint32(e[:], env)
	h := sha256.New()
	h.Write([]byte("sp/init\n"))
	h.Write(seed)
	h.Write(e[:])
	sum := h.Sum(nil)
	var r [8]uint32
	for i := range r {
		r[i] = binary.LittleEndian.Uint32(sum[i*4:])
	}
	return r
}

// FinalizeKey turns the VM's final registers into the session key Ks.
func FinalizeKey(salt []byte, r *[8]uint32, seed []byte, env uint32) []byte {
	var buf [36]byte
	for i, v := range r {
		binary.LittleEndian.PutUint32(buf[i*4:], v)
	}
	binary.LittleEndian.PutUint32(buf[32:], env)
	return MAC(salt, []byte("sp/ks\n"), buf[:], seed)
}

// Proof shows the client derived Ks for a given challenge string.
func Proof(ks []byte, challenge string) []byte {
	return MAC(ks, []byte("sp/proof\n"), []byte(challenge))
}

// RequestSig signs one HTTP request with the session key.
func RequestSig(ks []byte, method, path, query string, body []byte, ts, nonce string) []byte {
	bh := sha256.Sum256(body)
	nl := []byte("\n")
	return MAC(ks,
		[]byte("sp/req\n"),
		[]byte(method), nl,
		[]byte(path), nl,
		[]byte(query), nl,
		[]byte(hex.EncodeToString(bh[:])), nl,
		[]byte(ts), nl,
		[]byte(nonce))
}

// ---- proof of work (hashcash style) ----

func powPrefix(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("sp/pow\n"))
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(x)
	}
	return n
}

func powHash(prefix *[32]byte, counter uint64) [32]byte {
	var b [40]byte
	copy(b[:], prefix[:])
	binary.LittleEndian.PutUint64(b[32:], counter)
	return sha256.Sum256(b[:])
}

// PowCheck verifies a solution with a single hash.
func PowCheck(data []byte, counter uint64, zeroBits int) bool {
	if zeroBits <= 0 {
		return true
	}
	p := powPrefix(data)
	s := powHash(&p, counter)
	return leadingZeroBits(s[:]) >= zeroBits
}

// PowSolve searches for a counter; expected cost is 2^zeroBits hashes.
func PowSolve(data []byte, zeroBits int) uint64 {
	if zeroBits <= 0 {
		return 0
	}
	p := powPrefix(data)
	for c := uint64(0); ; c++ {
		s := powHash(&p, c)
		if leadingZeroBits(s[:]) >= zeroBits {
			return c
		}
	}
}

// ---- response sealing (AES-256-GCM) ----

func sealAEAD(ks []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(MAC(ks, []byte("sp/seal")))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts a response body. aad ties it to the request that asked for it.
// Output is nonce(12) || ciphertext+tag.
func Seal(ks, aad, plaintext []byte) ([]byte, error) {
	a, err := sealAEAD(ks)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal.
func Open(ks, aad, sealed []byte) ([]byte, error) {
	a, err := sealAEAD(ks)
	if err != nil {
		return nil, err
	}
	if len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, errors.New("sealed body too short")
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], aad)
}
