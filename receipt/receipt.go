// Package receipt defines the portable proof AuditAnchor hands to an auditor:
// a record's inclusion proof in a Merkle tree, plus external anchors (an
// OpenTimestamps proof) over that tree's head.
//
// The anchor commits to a tree head, not to the bare root, because an audit
// path alone does not bind the tree size. The head digest is
//
//	SHA-256("auditanchor/tree-head/v1" || 0x00 || uint64be(size) || root)
//
// so a receipt cannot be replayed against a different size, and an anchored
// head cannot be confused with any other SHA-256 value.
package receipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/octaviosantacruz/auditanchor/merkle"
	"github.com/octaviosantacruz/auditanchor/ots"
)

const (
	// Version is the receipt format version.
	Version = 1
	// Algorithm names the tree construction.
	Algorithm = "rfc6962-sha256"
	// AnchorOTS is the anchor type for an OpenTimestamps proof.
	AnchorOTS = "opentimestamps"

	headDomain   = "auditanchor/tree-head/v1"
	maxPathLen   = 64
	maxProofSize = 64 << 10
	maxReceipt   = 256 << 10
)

// HeadDigest returns the digest that anchors commit to for a tree head.
func HeadDigest(size uint64, root merkle.Hash) merkle.Hash {
	h := sha256.New()
	h.Write([]byte(headDomain))
	h.Write([]byte{0x00})
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], size)
	h.Write(n[:])
	h.Write(root[:])
	var out merkle.Hash
	h.Sum(out[:0])
	return out
}

// Receipt proves that one record is in a tree head and, once anchored, that
// the head existed no later than the anchor's time.
type Receipt struct {
	Version   int      `json:"version"`
	Algorithm string   `json:"algorithm"`
	TreeSize  uint64   `json:"tree_size"`
	Root      string   `json:"root"`
	LeafIndex uint64   `json:"leaf_index"`
	Path      []string `json:"path"`
	Anchors   []Anchor `json:"anchors,omitempty"`
}

// Anchor is an external commitment to the receipt's head digest.
type Anchor struct {
	Type  string `json:"type"`
	Proof []byte `json:"proof"` // base64 in JSON; for "opentimestamps", a serialized timestamp rooted at the head digest
}

// New returns an unanchored receipt for the leaf at index.
func New(tree *merkle.Tree, index uint64) (*Receipt, error) {
	proof, err := tree.InclusionProof(index)
	if err != nil {
		return nil, err
	}
	path := make([]string, len(proof))
	for i, h := range proof {
		path[i] = h.String()
	}
	return &Receipt{
		Version:   Version,
		Algorithm: Algorithm,
		TreeSize:  tree.Size(),
		Root:      tree.Root().String(),
		LeafIndex: index,
		Path:      path,
	}, nil
}

// Head returns the tree size and root.
func (r *Receipt) Head() (uint64, merkle.Hash, error) {
	root, err := merkle.ParseHash(r.Root)
	return r.TreeSize, root, err
}

// Digest returns the head digest anchors commit to.
func (r *Receipt) Digest() (merkle.Hash, error) {
	size, root, err := r.Head()
	if err != nil {
		return merkle.Hash{}, err
	}
	return HeadDigest(size, root), nil
}

// VerifyRecord checks that record is the leaf at LeafIndex under Root.
func (r *Receipt) VerifyRecord(record []byte) error {
	return r.VerifyLeaf(merkle.LeafHash(record))
}

// VerifyLeaf checks a precomputed leaf hash.
func (r *Receipt) VerifyLeaf(leaf merkle.Hash) error {
	if err := r.check(); err != nil {
		return err
	}
	_, root, err := r.Head()
	if err != nil {
		return err
	}
	path := make([]merkle.Hash, len(r.Path))
	for i, s := range r.Path {
		if path[i], err = merkle.ParseHash(s); err != nil {
			return err
		}
	}
	return merkle.VerifyInclusion(leaf, r.LeafIndex, r.TreeSize, path, root)
}

// SetTimestamp stores an OpenTimestamps proof, replacing any previous one.
// The timestamp must be rooted at the receipt's head digest.
func (r *Receipt) SetTimestamp(ts *ots.Timestamp) error {
	d, err := r.Digest()
	if err != nil {
		return err
	}
	if !bytes.Equal(ts.Msg, d[:]) {
		return errors.New("receipt: timestamp is not rooted at this receipt's head digest")
	}
	raw, err := ts.Serialize()
	if err != nil {
		return err
	}
	for i := range r.Anchors {
		if r.Anchors[i].Type == AnchorOTS {
			r.Anchors[i].Proof = raw
			return nil
		}
	}
	r.Anchors = append(r.Anchors, Anchor{Type: AnchorOTS, Proof: raw})
	return nil
}

// Timestamp returns the OpenTimestamps proof, or nil if there is none.
func (r *Receipt) Timestamp() (*ots.Timestamp, error) {
	d, err := r.Digest()
	if err != nil {
		return nil, err
	}
	for _, a := range r.Anchors {
		if a.Type == AnchorOTS {
			return ots.Parse(d[:], a.Proof)
		}
	}
	return nil, nil
}

// DetachedOTS exports the OpenTimestamps proof as a .ots file over the head
// digest, readable by the reference client ("ots info", "ots verify -d").
func (r *Receipt) DetachedOTS() ([]byte, error) {
	ts, err := r.Timestamp()
	if err != nil {
		return nil, err
	}
	if ts == nil {
		return nil, errors.New("receipt: no OpenTimestamps anchor")
	}
	return (&ots.DetachedFile{HashOp: ots.OpSHA256, Digest: ts.Msg, Timestamp: ts}).Serialize()
}

// Result is the outcome of Verify.
type Result struct {
	LeafIndex uint64
	TreeSize  uint64
	Root      string
	Digest    string
	// Bitcoin lists every Bitcoin attestation found (verified or not).
	Bitcoin []ots.BitcoinAttestation
	// Pending lists calendars that have not confirmed yet.
	Pending []string
	// Anchored is true when Bitcoin attestations were checked against a
	// header source; Height and Time are then the earliest confirmation.
	Anchored bool
	Height   uint64
	Time     time.Time
}

// Verify checks the record's inclusion and parses the anchor. If src is not
// nil, every Bitcoin attestation is also checked against its block header.
// Without src the result lists the attestations for the caller to check
// against a node of their own.
func (r *Receipt) Verify(ctx context.Context, record []byte, src ots.HeaderSource) (Result, error) {
	var res Result
	if err := r.VerifyRecord(record); err != nil {
		return res, err
	}
	d, _ := r.Digest() // valid: VerifyRecord parsed the root
	res = Result{LeafIndex: r.LeafIndex, TreeSize: r.TreeSize, Root: r.Root, Digest: d.String()}
	ts, err := r.Timestamp()
	if err != nil {
		return res, fmt.Errorf("receipt: anchor: %w", err)
	}
	if ts == nil {
		return res, nil
	}
	res.Bitcoin = ts.Bitcoin()
	res.Pending = ts.Pending()
	if src == nil || len(res.Bitcoin) == 0 {
		return res, nil
	}
	when, height, err := ots.VerifyBitcoin(ctx, ts, src)
	if err != nil {
		return res, err
	}
	res.Anchored, res.Height, res.Time = true, height, when
	return res, nil
}

func (r *Receipt) check() error {
	switch {
	case r.Version != Version:
		return fmt.Errorf("receipt: unsupported version %d", r.Version)
	case r.Algorithm != Algorithm:
		return fmt.Errorf("receipt: unsupported algorithm %q", r.Algorithm)
	case r.LeafIndex >= r.TreeSize:
		return fmt.Errorf("receipt: leaf index %d out of range for size %d", r.LeafIndex, r.TreeSize)
	case len(r.Path) > maxPathLen:
		return fmt.Errorf("receipt: path of %d hashes is too long", len(r.Path))
	}
	for _, a := range r.Anchors {
		if len(a.Proof) > maxProofSize {
			return fmt.Errorf("receipt: %s anchor exceeds %d bytes", a.Type, maxProofSize)
		}
	}
	return nil
}

// Decode parses a receipt strictly: unknown fields and trailing data are errors.
func Decode(data []byte) (*Receipt, error) {
	if len(data) > maxReceipt {
		return nil, fmt.Errorf("receipt: larger than %d bytes", maxReceipt)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Receipt
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	if dec.More() {
		return nil, errors.New("receipt: trailing data")
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	if _, _, err := r.Head(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Encode returns the receipt as indented JSON with a trailing newline.
func (r *Receipt) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
