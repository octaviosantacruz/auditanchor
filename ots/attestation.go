package ots

import (
	"bytes"
	"fmt"
)

// Attestation tags of the OpenTimestamps format.
var (
	TagBitcoin  = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	TagLitecoin = [8]byte{0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45}
	TagPending  = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
)

// Attestation states that the message at its position in the timestamp was
// committed somewhere: in a Bitcoin block header, or pending at a calendar.
// Unknown attestation kinds are preserved byte-for-byte.
type Attestation struct {
	Tag     [8]byte
	Payload []byte
}

// BitcoinHeight returns the block height if this is a Bitcoin attestation.
func (a Attestation) BitcoinHeight() (uint64, bool) {
	if a.Tag != TagBitcoin {
		return 0, false
	}
	r := &reader{b: a.Payload}
	h, err := r.varuint()
	if err != nil || !r.eof() {
		return 0, false
	}
	return h, true
}

// PendingURI returns the calendar URI if this is a pending attestation.
func (a Attestation) PendingURI() (string, bool) {
	if a.Tag != TagPending {
		return "", false
	}
	r := &reader{b: a.Payload}
	uri, err := r.varbytes(1, maxURILength)
	if err != nil || !r.eof() || !validURI(uri) {
		return "", false
	}
	return string(uri), true
}

// String renders the attestation for humans.
func (a Attestation) String() string {
	if h, ok := a.BitcoinHeight(); ok {
		return fmt.Sprintf("verify BitcoinBlockHeaderAttestation(%d)", h)
	}
	if u, ok := a.PendingURI(); ok {
		return fmt.Sprintf("verify PendingAttestation('%s')", u)
	}
	if a.Tag == TagLitecoin {
		return "verify LitecoinBlockHeaderAttestation"
	}
	return fmt.Sprintf("verify UnknownAttestation(%x)", a.Tag)
}

func validURI(b []byte) bool {
	for _, c := range b {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == '/' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

func newBitcoinAttestation(height uint64) Attestation {
	return Attestation{Tag: TagBitcoin, Payload: appendVaruint(nil, height)}
}

func newPendingAttestation(uri string) Attestation {
	return Attestation{Tag: TagPending, Payload: appendVarbytes(nil, []byte(uri))}
}

func readAttestation(r *reader) (Attestation, error) {
	tag, err := r.bytes(8)
	if err != nil {
		return Attestation{}, err
	}
	payload, err := r.varbytes(0, maxPayloadLength)
	if err != nil {
		return Attestation{}, err
	}
	a := Attestation{Payload: append([]byte(nil), payload...)}
	copy(a.Tag[:], tag)
	switch a.Tag {
	case TagBitcoin, TagLitecoin:
		pr := &reader{b: a.Payload}
		if _, err := pr.varuint(); err != nil || !pr.eof() {
			return Attestation{}, fmt.Errorf("%w: bad block header attestation", ErrMalformed)
		}
	case TagPending:
		if _, ok := a.PendingURI(); !ok {
			return Attestation{}, fmt.Errorf("%w: bad pending attestation", ErrMalformed)
		}
	}
	return a, nil
}

func (a Attestation) appendTo(dst []byte) []byte {
	dst = append(dst, a.Tag[:]...)
	return appendVarbytes(dst, a.Payload)
}

func (a Attestation) equal(b Attestation) bool {
	return a.Tag == b.Tag && bytes.Equal(a.Payload, b.Payload)
}

func (a Attestation) less(b Attestation) bool {
	if c := bytes.Compare(a.Tag[:], b.Tag[:]); c != 0 {
		return c < 0
	}
	return bytes.Compare(a.Payload, b.Payload) < 0
}
