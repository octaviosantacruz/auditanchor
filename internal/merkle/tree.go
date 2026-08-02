package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

type ProofStep struct {
	Side string `json:"side"`
	Hash string `json:"hash"`
}

type Tree struct {
	leaves [][]byte
	levels [][][]byte
}

func New(records [][]byte) *Tree {
	leaves := make([][]byte, 0, len(records))
	for _, record := range records {
		leaf := hashLeaf(record)
		leaves = append(leaves, leaf[:])
	}

	t := &Tree{leaves: leaves}
	if len(leaves) == 0 {
		return t
	}

	current := cloneLevel(leaves)
	t.levels = append(t.levels, current)
	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := left
			if i+1 < len(current) {
				right = current[i+1]
			}
			node := hashNode(left, right)
			next = append(next, node[:])
		}
		current = next
		t.levels = append(t.levels, current)
	}
	return t
}

func (t *Tree) RootHex() string {
	if len(t.levels) == 0 {
		empty := sha256.Sum256(nil)
		return hex.EncodeToString(empty[:])
	}
	root := t.levels[len(t.levels)-1][0]
	return hex.EncodeToString(root)
}

func (t *Tree) Proof(index int) []ProofStep {
	if index < 0 || index >= len(t.leaves) {
		return nil
	}
	proof := make([]ProofStep, 0, len(t.levels)-1)
	pos := index
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]
		sibling := pos ^ 1
		side := "right"
		if sibling < pos {
			side = "left"
		}
		if sibling >= len(nodes) {
			sibling = pos
		}
		proof = append(proof, ProofStep{Side: side, Hash: hex.EncodeToString(nodes[sibling])})
		pos /= 2
	}
	return proof
}

func Verify(record []byte, rootHex string, proof []ProofStep) bool {
	current := hashLeaf(record)
	node := current[:]
	for _, step := range proof {
		sibling, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false
		}
		var parent [32]byte
		if step.Side == "left" {
			parent = hashNode(sibling, node)
		} else {
			parent = hashNode(node, sibling)
		}
		node = parent[:]
	}
	return hex.EncodeToString(node) == rootHex
}

func hashLeaf(record []byte) [32]byte {
	payload := append([]byte{0x00}, record...)
	return sha256.Sum256(payload)
}

func hashNode(left, right []byte) [32]byte {
	payload := make([]byte, 0, 1+len(left)+len(right))
	payload = append(payload, 0x01)
	payload = append(payload, left...)
	payload = append(payload, right...)
	return sha256.Sum256(payload)
}

func cloneLevel(level [][]byte) [][]byte {
	out := make([][]byte, len(level))
	for i := range level {
		out[i] = append([]byte(nil), level[i]...)
	}
	return out
}
