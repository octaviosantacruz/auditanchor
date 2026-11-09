package ots

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // part of the OpenTimestamps format; never used to create new proofs
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // part of the OpenTimestamps format (early Bitcoin proofs)
	"golang.org/x/crypto/sha3"
)

// Op tags of the OpenTimestamps format.
const (
	OpSHA1      byte = 0x02
	OpRIPEMD160 byte = 0x03
	OpSHA256    byte = 0x08
	OpKeccak256 byte = 0x67
	OpAppend    byte = 0xf0
	OpPrepend   byte = 0xf1
	OpReverse   byte = 0xf2
	OpHexlify   byte = 0xf3
)

// Op is one commitment operation: it maps a message to a new message.
// Arg is set only for OpAppend and OpPrepend.
type Op struct {
	Tag byte
	Arg []byte
}

// Append returns an OpAppend.
func Append(b []byte) Op { return Op{Tag: OpAppend, Arg: append([]byte(nil), b...)} }

// Prepend returns an OpPrepend.
func Prepend(b []byte) Op { return Op{Tag: OpPrepend, Arg: append([]byte(nil), b...)} }

// SHA256 returns an OpSHA256.
func SHA256() Op { return Op{Tag: OpSHA256} }

func isBinary(tag byte) bool { return tag == OpAppend || tag == OpPrepend }

// digestLength returns the output length of a hash op, or 0 if tag is not one.
func digestLength(tag byte) int {
	switch tag {
	case OpSHA1, OpRIPEMD160:
		return 20
	case OpSHA256, OpKeccak256:
		return 32
	}
	return 0
}

func knownTag(tag byte) bool {
	return digestLength(tag) > 0 || isBinary(tag) || tag == OpReverse || tag == OpHexlify
}

// Apply returns the op's result for msg.
func (o Op) Apply(msg []byte) ([]byte, error) {
	if len(msg) > maxMsgLength {
		return nil, fmt.Errorf("%w: message of %d bytes exceeds limit", ErrMalformed, len(msg))
	}
	var out []byte
	switch o.Tag {
	case OpSHA1:
		s := sha1.Sum(msg) //nolint:gosec // verifying existing proofs only
		out = s[:]
	case OpRIPEMD160:
		h := ripemd160.New()
		h.Write(msg)
		out = h.Sum(nil)
	case OpSHA256:
		s := sha256.Sum256(msg)
		out = s[:]
	case OpKeccak256:
		h := sha3.NewLegacyKeccak256()
		h.Write(msg)
		out = h.Sum(nil)
	case OpAppend:
		out = append(append([]byte(nil), msg...), o.Arg...)
	case OpPrepend:
		out = append(append([]byte(nil), o.Arg...), msg...)
	case OpReverse:
		if len(msg) == 0 {
			return nil, fmt.Errorf("%w: reverse of empty message", ErrMalformed)
		}
		out = make([]byte, len(msg))
		for i, c := range msg {
			out[len(msg)-1-i] = c
		}
	case OpHexlify:
		if len(msg) == 0 || len(msg) > maxMsgLength/2 {
			return nil, fmt.Errorf("%w: hexlify of %d bytes", ErrMalformed, len(msg))
		}
		out = []byte(hex.EncodeToString(msg))
	default:
		return nil, fmt.Errorf("%w: unknown op 0x%02x", ErrMalformed, o.Tag)
	}
	if len(out) > maxMsgLength {
		return nil, fmt.Errorf("%w: op result of %d bytes exceeds limit", ErrMalformed, len(out))
	}
	return out, nil
}

func (o Op) equal(p Op) bool { return o.Tag == p.Tag && bytes.Equal(o.Arg, p.Arg) }

// less orders ops as the reference implementation does: by tag, then argument.
func (o Op) less(p Op) bool {
	if o.Tag != p.Tag {
		return o.Tag < p.Tag
	}
	return bytes.Compare(o.Arg, p.Arg) < 0
}

func (o Op) appendTo(dst []byte) []byte {
	dst = append(dst, o.Tag)
	if isBinary(o.Tag) {
		dst = appendVarbytes(dst, o.Arg)
	}
	return dst
}

func readOp(r *reader, tag byte) (Op, error) {
	if !knownTag(tag) {
		return Op{}, fmt.Errorf("%w: unknown op 0x%02x", ErrMalformed, tag)
	}
	op := Op{Tag: tag}
	if isBinary(tag) {
		arg, err := r.varbytes(1, maxMsgLength)
		if err != nil {
			return Op{}, err
		}
		op.Arg = append([]byte(nil), arg...)
	}
	return op, nil
}

// String renders the op like the reference client's "ots info".
func (o Op) String() string {
	names := map[byte]string{
		OpSHA1: "sha1", OpRIPEMD160: "ripemd160", OpSHA256: "sha256", OpKeccak256: "keccak256",
		OpAppend: "append", OpPrepend: "prepend", OpReverse: "reverse", OpHexlify: "hexlify",
	}
	name, ok := names[o.Tag]
	if !ok {
		name = fmt.Sprintf("op(0x%02x)", o.Tag)
	}
	if isBinary(o.Tag) {
		return name + " " + hex.EncodeToString(o.Arg)
	}
	return name
}
