// Package ots reads, writes, creates and upgrades OpenTimestamps proofs and
// checks their Bitcoin attestations against block headers.
//
// A Timestamp is a tree of commitment operations rooted at a message (here, an
// AuditAnchor tree head). Each path ends in an attestation: pending at a
// calendar server, or confirmed in a Bitcoin block whose header Merkle root
// equals the message reached at that point.
package ots

import (
	"bytes"
	"fmt"
	"sort"
)

// Timestamp is a proof that Msg existed. Its branches apply an Op to Msg and
// continue with the resulting message.
type Timestamp struct {
	Msg          []byte
	Attestations []Attestation
	Branches     []Branch
}

// Branch is one operation applied to the parent's message.
type Branch struct {
	Op   Op
	Next *Timestamp
}

// New returns an empty timestamp for msg.
func New(msg []byte) *Timestamp { return &Timestamp{Msg: append([]byte(nil), msg...)} }

// Add applies op to t.Msg and returns the (new or existing) child timestamp.
func (t *Timestamp) Add(op Op) (*Timestamp, error) {
	for _, b := range t.Branches {
		if b.Op.equal(op) {
			return b.Next, nil
		}
	}
	msg, err := op.Apply(t.Msg)
	if err != nil {
		return nil, err
	}
	next := &Timestamp{Msg: msg}
	t.Branches = append(t.Branches, Branch{Op: op, Next: next})
	return next, nil
}

func (t *Timestamp) addAttestation(a Attestation) {
	for _, x := range t.Attestations {
		if x.equal(a) {
			return
		}
	}
	t.Attestations = append(t.Attestations, a)
}

// Merge adds every attestation and branch of o into t. Both must be rooted at
// the same message.
func (t *Timestamp) Merge(o *Timestamp) error {
	if !bytes.Equal(t.Msg, o.Msg) {
		return fmt.Errorf("ots: cannot merge timestamps of different messages")
	}
	for _, a := range o.Attestations {
		t.addAttestation(a)
	}
	for _, ob := range o.Branches {
		next, err := t.Add(ob.Op)
		if err != nil {
			return err
		}
		if err := next.Merge(ob.Next); err != nil {
			return err
		}
	}
	return nil
}

// Found is an attestation together with the message it attests.
type Found struct {
	Msg         []byte
	Attestation Attestation
}

// All returns every attestation in the tree with its message.
func (t *Timestamp) All() []Found {
	var out []Found
	t.walk(func(n *Timestamp) {
		for _, a := range n.Attestations {
			out = append(out, Found{Msg: n.Msg, Attestation: a})
		}
	})
	return out
}

// Pending returns the calendar URIs still awaiting confirmation.
func (t *Timestamp) Pending() []string {
	var out []string
	for _, f := range t.All() {
		if u, ok := f.Attestation.PendingURI(); ok {
			out = append(out, u)
		}
	}
	return out
}

// Bitcoin returns the Bitcoin attestations, each with the header Merkle root
// (internal byte order) that the block at Height must contain.
func (t *Timestamp) Bitcoin() []BitcoinAttestation {
	var out []BitcoinAttestation
	for _, f := range t.All() {
		if h, ok := f.Attestation.BitcoinHeight(); ok {
			out = append(out, BitcoinAttestation{Height: h, MerkleRoot: f.Msg})
		}
	}
	return out
}

func (t *Timestamp) walk(fn func(*Timestamp)) {
	fn(t)
	for _, b := range t.Branches {
		b.Next.walk(fn)
	}
}

// Parse decodes a serialized timestamp (no file header) rooted at msg. The
// whole input must be consumed.
func Parse(msg, data []byte) (*Timestamp, error) {
	r := &reader{b: data}
	t, err := readTimestamp(r, append([]byte(nil), msg...), 0)
	if err != nil {
		return nil, err
	}
	if !r.eof() {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(data)-r.off)
	}
	return t, nil
}

func readTimestamp(r *reader, msg []byte, depth int) (*Timestamp, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, maxDepth)
	}
	t := &Timestamp{Msg: msg}
	item := func(tag byte) error {
		if tag == 0x00 {
			a, err := readAttestation(r)
			if err != nil {
				return err
			}
			t.Attestations = append(t.Attestations, a)
			return nil
		}
		op, err := readOp(r, tag)
		if err != nil {
			return err
		}
		next, err := op.Apply(msg)
		if err != nil {
			return err
		}
		child, err := readTimestamp(r, next, depth+1)
		if err != nil {
			return err
		}
		t.Branches = append(t.Branches, Branch{Op: op, Next: child})
		return nil
	}
	tag, err := r.byte()
	if err != nil {
		return nil, err
	}
	for tag == 0xff {
		next, err := r.byte()
		if err != nil {
			return nil, err
		}
		if err := item(next); err != nil {
			return nil, err
		}
		if tag, err = r.byte(); err != nil {
			return nil, err
		}
	}
	if err := item(tag); err != nil {
		return nil, err
	}
	return t, nil
}

// Serialize encodes t canonically: attestations then branches, each sorted as
// the reference implementation sorts them, so parse/serialize round-trips.
func (t *Timestamp) Serialize() ([]byte, error) {
	return t.appendTo(nil)
}

func (t *Timestamp) appendTo(dst []byte) ([]byte, error) {
	if len(t.Attestations) == 0 && len(t.Branches) == 0 {
		return nil, fmt.Errorf("ots: timestamp node has neither attestations nor operations")
	}
	atts := append([]Attestation(nil), t.Attestations...)
	sort.Slice(atts, func(i, j int) bool { return atts[i].less(atts[j]) })
	branches := append([]Branch(nil), t.Branches...)
	sort.Slice(branches, func(i, j int) bool { return branches[i].Op.less(branches[j].Op) })

	total := len(atts) + len(branches)
	n := 0
	sep := func() {
		n++
		if n < total {
			dst = append(dst, 0xff)
		}
	}
	for _, a := range atts {
		sep()
		dst = append(dst, 0x00)
		dst = a.appendTo(dst)
	}
	var err error
	for _, b := range branches {
		sep()
		dst = b.Op.appendTo(dst)
		if dst, err = b.Next.appendTo(dst); err != nil {
			return nil, err
		}
	}
	return dst, nil
}
