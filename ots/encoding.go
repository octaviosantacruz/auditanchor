package ots

import (
	"errors"
	"fmt"
)

// Limits match the reference implementation (python-opentimestamps) so that
// any proof it accepts is accepted here and hostile input stays bounded.
const (
	maxMsgLength     = 4096 // longest message an op may produce
	maxPayloadLength = 8192 // longest attestation payload
	maxURILength     = 1000 // longest pending-attestation calendar URI
	maxDepth         = 256  // deepest nesting of ops
)

// ErrMalformed is returned (wrapped) for any proof that cannot be decoded.
var ErrMalformed = errors.New("ots: malformed proof")

type reader struct {
	b   []byte
	off int
}

func (r *reader) eof() bool { return r.off >= len(r.b) }

func (r *reader) byte() (byte, error) {
	if r.off >= len(r.b) {
		return 0, fmt.Errorf("%w: unexpected end of data", ErrMalformed)
	}
	c := r.b[r.off]
	r.off++
	return c, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || len(r.b)-r.off < n {
		return nil, fmt.Errorf("%w: unexpected end of data", ErrMalformed)
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, nil
}

// varuint is unsigned LEB128, capped at 63 bits.
func (r *reader) varuint() (uint64, error) {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		if shift > 56 {
			return 0, fmt.Errorf("%w: varuint too long", ErrMalformed)
		}
		c, err := r.byte()
		if err != nil {
			return 0, err
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
	}
}

func (r *reader) varbytes(min, max int) ([]byte, error) {
	n, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if n < uint64(min) || n > uint64(max) {
		return nil, fmt.Errorf("%w: length %d outside [%d, %d]", ErrMalformed, n, min, max)
	}
	return r.bytes(int(n))
}

func appendVaruint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendVarbytes(dst, b []byte) []byte {
	return append(appendVaruint(dst, uint64(len(b))), b...)
}
