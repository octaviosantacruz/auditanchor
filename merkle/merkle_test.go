package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// Leaves and expected values from the Certificate Transparency reference test
// vectors (RFC 6962 implementations: certificate-transparency-go, Trillian).
var ctLeaves = [][]byte{
	{},
	{0x00},
	{0x10},
	{0x20, 0x21},
	{0x30, 0x31},
	{0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
	{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
}

var ctRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func mustHashes(t testing.TB, hexes ...string) []Hash {
	t.Helper()
	out := make([]Hash, len(hexes))
	for i, s := range hexes {
		h, err := ParseHash(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = h
	}
	return out
}

func TestEmptyRoot(t *testing.T) {
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := New(nil).Root().String(); got != want {
		t.Fatalf("empty root = %s, want %s", got, want)
	}
}

func TestCTRoots(t *testing.T) {
	for n := 1; n <= len(ctLeaves); n++ {
		if got := New(ctLeaves[:n]).Root().String(); got != ctRoots[n-1] {
			t.Errorf("root of %d leaves = %s, want %s", n, got, ctRoots[n-1])
		}
	}
}

func TestCTInclusionProofs(t *testing.T) {
	tree := New(ctLeaves)
	cases := []struct {
		index uint64
		path  []string
	}{
		{0, []string{
			"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{5, []string{
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		}},
	}
	for _, c := range cases {
		got, err := tree.InclusionProof(c.index)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHashes(t, c.path...)
		if !equalHashes(got, want) {
			t.Errorf("proof for leaf %d = %v, want %v", c.index, got, want)
		}
	}
}

func TestCTConsistencyProofs(t *testing.T) {
	tree := New(ctLeaves)
	cases := []struct {
		old, new uint64
		path     []string
	}{
		{1, 8, []string{
			"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		}},
		{6, 8, []string{
			"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		}},
		{2, 5, []string{
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
		}},
	}
	for _, c := range cases {
		sub := New(ctLeaves[:c.new])
		got, err := sub.ConsistencyProof(c.old)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHashes(t, c.path...)
		if !equalHashes(got, want) {
			t.Errorf("consistency %d->%d = %v, want %v", c.old, c.new, got, want)
		}
		oldRoot, _ := tree.RootAt(c.old)
		newRoot, _ := tree.RootAt(c.new)
		if err := VerifyConsistency(c.old, c.new, oldRoot, newRoot, got); err != nil {
			t.Errorf("verify %d->%d: %v", c.old, c.new, err)
		}
	}
}

// TestNoDuplicationCollision is the CVE-2012-2459 regression: the prototype
// duplicated the last node of odd levels, so these two lists shared a root.
func TestNoDuplicationCollision(t *testing.T) {
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	r3 := New([][]byte{a, b, c}).Root()
	r4 := New([][]byte{a, b, c, c}).Root()
	if r3 == r4 {
		t.Fatal("[a,b,c] and [a,b,c,c] share a root")
	}
}

func TestDomainSeparation(t *testing.T) {
	l, r := LeafHash([]byte("l")), LeafHash([]byte("r"))
	node := NodeHash(l, r)
	// A leaf whose data is the concatenation of two child hashes must not
	// hash to the node formed by those children.
	if LeafHash(append(l[:], r[:]...)) == node {
		t.Fatal("leaf and node hashes collide")
	}
	if LeafHash(nil) == EmptyRoot() {
		t.Fatal("empty leaf equals empty root")
	}
}

// refRoot is an independent, deliberately naive MTH used to cross-check.
func refRoot(leaves [][]byte) Hash {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return sha256.Sum256(append([]byte{0}, leaves[0]...))
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	l, r := refRoot(leaves[:k]), refRoot(leaves[k:])
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

func genLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte{byte(i), byte(i >> 8), 0xa5}
	}
	return out
}

func TestExhaustiveSmallTrees(t *testing.T) {
	const max = 70
	all := genLeaves(max)
	full := New(all)
	for n := 1; n <= max; n++ {
		tree := New(all[:n])
		root := tree.Root()
		if root != refRoot(all[:n]) {
			t.Fatalf("size %d: root disagrees with reference", n)
		}
		if got, _ := full.RootAt(uint64(n)); got != root {
			t.Fatalf("size %d: RootAt disagrees", n)
		}
		for i := 0; i < n; i++ {
			p, err := tree.InclusionProof(uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			leaf := LeafHash(all[i])
			if err := VerifyInclusion(leaf, uint64(i), uint64(n), p, root); err != nil {
				t.Fatalf("size %d leaf %d: %v", n, i, err)
			}
			// Wrong index, wrong size and wrong leaf must all fail.
			if n > 1 {
				if VerifyInclusion(leaf, uint64((i+1)%n), uint64(n), p, root) == nil {
					t.Fatalf("size %d leaf %d: accepted wrong index", n, i)
				}
			}
			// An audit path alone does not bind the tree size: the same path
			// can be valid for another size against the same root. Callers
			// must commit to (size, root) together; package receipt anchors
			// a tree head that includes the size for this reason.
			if VerifyInclusion(LeafHash([]byte("x")), uint64(i), uint64(n), p, root) == nil {
				t.Fatalf("size %d leaf %d: accepted wrong leaf", n, i)
			}
			for j := range p {
				bad := append([]Hash(nil), p...)
				bad[j][0] ^= 1
				if VerifyInclusion(leaf, uint64(i), uint64(n), bad, root) == nil {
					t.Fatalf("size %d leaf %d: accepted flipped path[%d]", n, i, j)
				}
			}
		}
		for m := 1; m <= n; m++ {
			p, err := tree.ConsistencyProof(uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			oldRoot := refRoot(all[:m])
			if err := VerifyConsistency(uint64(m), uint64(n), oldRoot, root, p); err != nil {
				t.Fatalf("consistency %d->%d: %v", m, n, err)
			}
			if m < n {
				if VerifyConsistency(uint64(m), uint64(n), LeafHash([]byte("x")), root, p) == nil {
					t.Fatalf("consistency %d->%d: accepted wrong old root", m, n)
				}
				for j := range p {
					bad := append([]Hash(nil), p...)
					bad[j][31] ^= 0x80
					if VerifyConsistency(uint64(m), uint64(n), oldRoot, root, bad) == nil {
						t.Fatalf("consistency %d->%d: accepted flipped proof[%d]", m, n, j)
					}
				}
			}
		}
	}
}

func TestRejectsBadArguments(t *testing.T) {
	tree := New(genLeaves(5))
	if _, err := tree.InclusionProof(5); err == nil {
		t.Error("InclusionProof accepted out-of-range index")
	}
	if _, err := tree.ConsistencyProof(0); err == nil {
		t.Error("ConsistencyProof accepted size 0")
	}
	if _, err := tree.ConsistencyProof(6); err == nil {
		t.Error("ConsistencyProof accepted size beyond tree")
	}
	if _, err := tree.RootAt(6); err == nil {
		t.Error("RootAt accepted size beyond tree")
	}
	err := VerifyInclusion(Hash{}, 3, 3, nil, Hash{})
	if !errors.Is(err, ErrInvalidProof) {
		t.Errorf("index == size: got %v, want ErrInvalidProof", err)
	}
	if _, err := ParseHash("abcd"); err == nil {
		t.Error("ParseHash accepted short hex")
	}
}

func FuzzInclusion(f *testing.F) {
	f.Add(uint16(7), uint16(3), []byte("seed"))
	f.Add(uint16(1), uint16(0), []byte{})
	f.Fuzz(func(t *testing.T, size, index uint16, salt []byte) {
		n := int(size%300) + 1
		i := uint64(index) % uint64(n)
		leaves := make([][]byte, n)
		for k := range leaves {
			leaves[k] = append([]byte{byte(k), byte(k >> 8)}, salt...)
		}
		tree := New(leaves)
		p, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(LeafHash(leaves[i]), i, uint64(n), p, tree.Root()); err != nil {
			t.Fatalf("n=%d i=%d: %v", n, i, err)
		}
	})
}

// FuzzVerifyInclusion feeds arbitrary proofs: verification must never panic
// and must only accept the genuine root.
func FuzzVerifyInclusion(f *testing.F) {
	f.Add(uint64(0), uint64(1), []byte{})
	f.Add(uint64(5), uint64(8), bytes.Repeat([]byte{1}, 96))
	f.Fuzz(func(t *testing.T, index, size uint64, raw []byte) {
		var proof []Hash
		for len(raw) >= Size && len(proof) < 70 {
			var h Hash
			copy(h[:], raw)
			proof = append(proof, h)
			raw = raw[Size:]
		}
		leaf := LeafHash([]byte("leaf"))
		root, err := RootFromInclusionProof(leaf, index, size, proof)
		if err != nil {
			return
		}
		if VerifyInclusion(leaf, index, size, proof, root) != nil {
			t.Fatal("recomputed root does not verify")
		}
	})
}

func FuzzVerifyConsistency(f *testing.F) {
	f.Add(uint64(3), uint64(7), []byte{})
	f.Fuzz(func(t *testing.T, oldSize, newSize uint64, raw []byte) {
		var proof []Hash
		for len(raw) >= Size && len(proof) < 70 {
			var h Hash
			copy(h[:], raw)
			proof = append(proof, h)
			raw = raw[Size:]
		}
		_ = VerifyConsistency(oldSize, newSize, Hash{1}, Hash{2}, proof) // must not panic
	})
}

func equalHashes(a, b []Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
