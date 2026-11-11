// Package vm is the server side of the polymorphic key-derivation machine.
//
// Two things change over time:
//   - the Program (a random instruction sequence) changes every epoch;
//   - the Spec (how instructions are encoded on the wire and which constants
//     each operation uses) changes per WASM variant, i.e. per build of the pool.
//
// The server runs programs with the table-driven interpreter below. Each
// client WASM variant carries the same semantics as generated straight-line
// code with the Spec's constants inlined (see cmd/spgen), so an attacker who
// re-implements one variant has to redo the work when the pool is rebuilt.
package vm

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"

	"statelessprotection/internal/proto"
)

const (
	NumOps    = 8
	InstrSize = 6
)

// OpBodies is the Go source of each canonical operation. $K and $T are
// replaced with the variant's constants by the generator. Spec.Run below must
// stay in sync with these; the e2e test checks every built variant against it.
var OpBodies = [NumOps]string{
	0: "r[a] += r[b] + imm + $K",
	1: "r[a] ^= r[b] ^ imm ^ $K",
	2: "r[a] = bits.RotateLeft32(r[a]^$K, int(imm&31|1))",
	3: "r[a] = r[a]*(imm|1) + r[b] + $K",
	4: "r[a] = r[a] - (r[b] ^ $K) - imm",
	5: "r[a] ^= r[a] >> $T; r[a] *= $K | 1; r[a] += imm",
	6: "r[a], r[b] = r[b]+imm, r[a]^$K",
	7: "r[a] = bits.RotateLeft32(r[a]+r[b], $T) ^ imm",
}

// Spec describes one WASM variant.
type Spec struct {
	OpXor   byte           // wire opcode byte is XORed with this
	OpPerm  [NumOps]byte   // (wire^OpXor)&7 -> canonical op
	RegPerm [8]byte        // wire register -> real register
	ImmMask uint32         // immediates are XORed with this on the wire
	K       [NumOps]uint32 // per-operation constant
	Rot     [NumOps]byte   // per-operation shift/rotate amount, 1..31
	Salt    [16]byte       // final key-derivation salt
}

// Instr is one canonical instruction. Pad carries random filler bits used
// by the wire encoding.
type Instr struct {
	Op, A, B byte
	Imm      uint32
	Pad      [2]byte
}

// drbg is a deterministic byte stream: HMAC(key, label || counter).
type drbg struct {
	key, label []byte
	ctr        uint64
	buf        []byte
}

func (d *drbg) next() byte {
	if len(d.buf) == 0 {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.ctr)
		d.ctr++
		d.buf = proto.MAC(d.key, d.label, c[:])
	}
	b := d.buf[0]
	d.buf = d.buf[1:]
	return b
}

func (d *drbg) u32() uint32 {
	return uint32(d.next()) | uint32(d.next())<<8 | uint32(d.next())<<16 | uint32(d.next())<<24
}

func (d *drbg) intn(n int) int { return int(d.u32() % uint32(n)) }

func (d *drbg) perm8() [8]byte {
	p := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
	for i := 7; i > 0; i-- {
		j := d.intn(i + 1)
		p[i], p[j] = p[j], p[i]
	}
	return p
}

func idxBytes(idx int) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(idx))
	return b[:]
}

// DeriveSpec deterministically derives variant idx of a pool.
func DeriveSpec(poolSeed []byte, idx int) Spec {
	d := &drbg{key: poolSeed, label: append([]byte("sp/spec\n"), idxBytes(idx)...)}
	var s Spec
	s.OpXor = d.next()
	s.OpPerm = d.perm8()
	s.RegPerm = d.perm8()
	s.ImmMask = d.u32()
	for i := range s.K {
		s.K[i] = d.u32()
		s.Rot[i] = byte(1 + d.intn(31))
	}
	for i := range s.Salt {
		s.Salt[i] = d.next()
	}
	return s
}

// Name is the unguessable file stem of a variant's .wasm file.
func Name(poolSeed []byte, idx int) string {
	return hex.EncodeToString(proto.MAC(poolSeed, []byte("sp/name\n"), idxBytes(idx)))[:20]
}

// GenProgram deterministically generates n instructions from key.
func GenProgram(key []byte, n int) []Instr {
	d := &drbg{key: key, label: []byte("sp/prog\n")}
	out := make([]Instr, n)
	for i := range out {
		a := d.intn(8)
		out[i] = Instr{
			Op:  byte(d.intn(NumOps)),
			A:   byte(a),
			B:   byte((a + 1 + d.intn(7)) % 8), // never equal to A
			Imm: d.u32(),
			Pad: [2]byte{d.next(), d.next()},
		}
	}
	return out
}

// Encode serialises a program in this variant's wire format.
func (s *Spec) Encode(prog []Instr) []byte {
	var invOp, invReg [8]byte
	for i := 0; i < 8; i++ {
		invOp[s.OpPerm[i]] = byte(i)
		invReg[s.RegPerm[i]] = byte(i)
	}
	out := make([]byte, 0, len(prog)*InstrSize)
	for _, in := range prog {
		var b [InstrSize]byte
		b[0] = (in.Pad[0]&0xF8 | invOp[in.Op]) ^ s.OpXor
		b[1] = in.Pad[1]&0xC0 | invReg[in.B]<<3 | invReg[in.A]
		binary.LittleEndian.PutUint32(b[2:], in.Imm^s.ImmMask)
		out = append(out, b[:]...)
	}
	return out
}

// Run executes a wire-encoded program over the registers.
func (s *Spec) Run(r *[8]uint32, p []byte) {
	for i := 0; i+InstrSize <= len(p); i += InstrSize {
		op := s.OpPerm[(p[i]^s.OpXor)&7]
		a := s.RegPerm[p[i+1]&7]
		b := s.RegPerm[(p[i+1]>>3)&7]
		imm := binary.LittleEndian.Uint32(p[i+2:]) ^ s.ImmMask
		k, t := s.K[op], int(s.Rot[op])
		switch op {
		case 0:
			r[a] += r[b] + imm + k
		case 1:
			r[a] ^= r[b] ^ imm ^ k
		case 2:
			r[a] = bits.RotateLeft32(r[a]^k, int(imm&31|1))
		case 3:
			r[a] = r[a]*(imm|1) + r[b] + k
		case 4:
			r[a] = r[a] - (r[b] ^ k) - imm
		case 5:
			r[a] ^= r[a] >> t
			r[a] *= k | 1
			r[a] += imm
		case 6:
			r[a], r[b] = r[b]+imm, r[a]^k
		case 7:
			r[a] = bits.RotateLeft32(r[a]+r[b], t) ^ imm
		}
	}
}
