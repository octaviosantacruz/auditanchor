package ots

import (
	"bytes"
	"fmt"
)

// headerMagic opens every detached .ots file.
var headerMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

const majorVersion = 1

// DetachedFile is a .ots file: the hash of the stamped content plus its
// timestamp. It is what the reference "ots" client reads and writes.
type DetachedFile struct {
	HashOp    byte // OpSHA256 for AuditAnchor tree heads
	Digest    []byte
	Timestamp *Timestamp
}

// ParseDetached decodes a .ots file.
func ParseDetached(data []byte) (*DetachedFile, error) {
	if !bytes.HasPrefix(data, headerMagic) {
		return nil, fmt.Errorf("%w: not an OpenTimestamps proof file", ErrMalformed)
	}
	r := &reader{b: data, off: len(headerMagic)}
	v, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if v != majorVersion {
		return nil, fmt.Errorf("%w: unsupported major version %d", ErrMalformed, v)
	}
	op, err := r.byte()
	if err != nil {
		return nil, err
	}
	n := digestLength(op)
	if n == 0 {
		return nil, fmt.Errorf("%w: file hash op 0x%02x is not a hash", ErrMalformed, op)
	}
	digest, err := r.bytes(n)
	if err != nil {
		return nil, err
	}
	ts, err := Parse(digest, data[r.off:])
	if err != nil {
		return nil, err
	}
	return &DetachedFile{HashOp: op, Digest: append([]byte(nil), digest...), Timestamp: ts}, nil
}

// Serialize encodes d as a .ots file.
func (d *DetachedFile) Serialize() ([]byte, error) {
	if digestLength(d.HashOp) != len(d.Digest) {
		return nil, fmt.Errorf("ots: digest length %d does not match hash op 0x%02x", len(d.Digest), d.HashOp)
	}
	if !bytes.Equal(d.Timestamp.Msg, d.Digest) {
		return nil, fmt.Errorf("ots: timestamp is not rooted at the digest")
	}
	out := append([]byte(nil), headerMagic...)
	out = appendVaruint(out, majorVersion)
	out = append(out, d.HashOp)
	out = append(out, d.Digest...)
	return d.Timestamp.appendTo(out)
}
