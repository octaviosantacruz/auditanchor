// Package merkle implements the Merkle tree of RFC 6962 / RFC 9162 (Certificate
// Transparency) over SHA-256: tree heads, inclusion proofs and consistency
// proofs, with their verification algorithms.
//
// Leaves and interior nodes are domain-separated (0x00 and 0x01 prefixes), so a
// leaf can never be confused with a node. A tree whose size is not a power of
// two is split at the largest power of two smaller than its size; no node is
// ever duplicated, so distinct leaf lists never share a root (the duplication
// scheme Bitcoin uses allows [a,b,c] and [a,b,c,c] to collide, CVE-2012-2459).
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// Size is the length in bytes of every hash in the tree.
const Size = sha256.Size

// Hash is a leaf, node or root hash.
type Hash [Size]byte

// String returns the lowercase hex encoding of h.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash decodes a 64-character hex string.
func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("merkle: invalid hash hex: %w", err)
	}
	if len(b) != Size {
		return h, fmt.Errorf("merkle: hash is %d bytes, want %d", len(b), Size)
	}
	copy(h[:], b)
	return h, nil
}

// ErrInvalidProof is returned (wrapped) whenever a proof does not verify.
var ErrInvalidProof = errors.New("merkle: invalid proof")

// EmptyRoot is the root of the tree with no leaves: SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// LeafHash returns SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash returns SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// Tree is an immutable list of leaf hashes. It keeps only leaf hashes, never
// the records themselves, so it can be built from data that stays private.
type Tree struct {
	leaves []Hash
}

// New hashes each record as a leaf. Records are taken byte-for-byte: callers
// decide the canonical form (for example, a JSON line without its newline).
func New(records [][]byte) *Tree {
	leaves := make([]Hash, len(records))
	for i, r := range records {
		leaves[i] = LeafHash(r)
	}
	return &Tree{leaves: leaves}
}

// FromLeafHashes builds a tree from precomputed leaf hashes. The slice is copied.
func FromLeafHashes(leaves []Hash) *Tree {
	return &Tree{leaves: append([]Hash(nil), leaves...)}
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

// Leaf returns the leaf hash at index.
func (t *Tree) Leaf(index uint64) (Hash, error) {
	if index >= t.Size() {
		return Hash{}, fmt.Errorf("merkle: leaf index %d out of range for size %d", index, t.Size())
	}
	return t.leaves[index], nil
}

// Root returns the Merkle tree hash of all leaves.
func (t *Tree) Root() Hash {
	if len(t.leaves) == 0 {
		return EmptyRoot()
	}
	return mth(t.leaves)
}

// RootAt returns the root of the tree formed by the first size leaves.
func (t *Tree) RootAt(size uint64) (Hash, error) {
	if size > t.Size() {
		return Hash{}, fmt.Errorf("merkle: size %d exceeds tree size %d", size, t.Size())
	}
	if size == 0 {
		return EmptyRoot(), nil
	}
	return mth(t.leaves[:size]), nil
}

// InclusionProof returns the audit path for the leaf at index in the full tree.
func (t *Tree) InclusionProof(index uint64) ([]Hash, error) {
	if index >= t.Size() {
		return nil, fmt.Errorf("merkle: leaf index %d out of range for size %d", index, t.Size())
	}
	return path(index, t.leaves), nil
}

// ConsistencyProof proves that the tree of the first oldSize leaves is a prefix
// of the full tree, i.e. the log was only appended to. oldSize must be in
// [1, Size]; for oldSize == Size the proof is empty.
func (t *Tree) ConsistencyProof(oldSize uint64) ([]Hash, error) {
	if oldSize == 0 || oldSize > t.Size() {
		return nil, fmt.Errorf("merkle: consistency from size %d to %d is undefined", oldSize, t.Size())
	}
	if oldSize == t.Size() {
		return nil, nil
	}
	return subproof(oldSize, t.leaves, true), nil
}

// mth is MTH(D[n]) for n >= 1.
func mth(d []Hash) Hash {
	if len(d) == 1 {
		return d[0]
	}
	k := split(uint64(len(d)))
	return NodeHash(mth(d[:k]), mth(d[k:]))
}

// path is PATH(m, D[n]) from RFC 6962 section 2.1.1.
func path(m uint64, d []Hash) []Hash {
	n := uint64(len(d))
	if n == 1 {
		return nil
	}
	k := split(n)
	if m < k {
		return append(path(m, d[:k]), mth(d[k:]))
	}
	return append(path(m-k, d[k:]), mth(d[:k]))
}

// subproof is SUBPROOF(m, D[n], b) from RFC 6962 section 2.1.2.
func subproof(m uint64, d []Hash, b bool) []Hash {
	n := uint64(len(d))
	if m == n {
		if b {
			return nil
		}
		return []Hash{mth(d)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(m, d[:k], b), mth(d[k:]))
	}
	return append(subproof(m-k, d[k:], false), mth(d[:k]))
}

// split returns the largest power of two strictly smaller than n (n >= 2).
func split(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// RootFromInclusionProof recomputes the root implied by a leaf hash, its index,
// the tree size and the audit path (RFC 9162 section 2.1.3.2).
func RootFromInclusionProof(leaf Hash, index, size uint64, proof []Hash) (Hash, error) {
	if index >= size {
		return Hash{}, fmt.Errorf("%w: leaf index %d out of range for size %d", ErrInvalidProof, index, size)
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return Hash{}, fmt.Errorf("%w: proof too long", ErrInvalidProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return Hash{}, fmt.Errorf("%w: proof too short", ErrInvalidProof)
	}
	return r, nil
}

// VerifyInclusion checks that leaf is at index in the tree of the given size
// and root.
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	got, err := RootFromInclusionProof(leaf, index, size, proof)
	if err != nil {
		return err
	}
	if got != root {
		return fmt.Errorf("%w: computed root %s, want %s", ErrInvalidProof, got, root)
	}
	return nil
}

// VerifyConsistency checks that the tree of oldSize leaves with oldRoot is a
// prefix of the tree of newSize leaves with newRoot (RFC 9162 section 2.1.4.2).
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot Hash, proof []Hash) error {
	switch {
	case oldSize > newSize:
		return fmt.Errorf("%w: old size %d exceeds new size %d", ErrInvalidProof, oldSize, newSize)
	case oldSize == newSize:
		if len(proof) != 0 {
			return fmt.Errorf("%w: equal sizes need an empty proof", ErrInvalidProof)
		}
		if oldRoot != newRoot {
			return fmt.Errorf("%w: equal sizes with different roots", ErrInvalidProof)
		}
		return nil
	case oldSize == 0:
		// Every tree extends the empty tree; there is nothing to prove.
		if len(proof) != 0 {
			return fmt.Errorf("%w: empty old tree needs an empty proof", ErrInvalidProof)
		}
		return nil
	}
	if len(proof) == 0 {
		return fmt.Errorf("%w: empty proof", ErrInvalidProof)
	}
	if oldSize&(oldSize-1) == 0 { // exact power of two: old root is a node of the new tree
		proof = append([]Hash{oldRoot}, proof...)
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: proof too long", ErrInvalidProof)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: proof too short", ErrInvalidProof)
	}
	if fr != oldRoot {
		return fmt.Errorf("%w: old root mismatch", ErrInvalidProof)
	}
	if sr != newRoot {
		return fmt.Errorf("%w: new root mismatch", ErrInvalidProof)
	}
	return nil
}
