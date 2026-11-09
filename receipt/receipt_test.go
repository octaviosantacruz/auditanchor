package receipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"

	"github.com/octaviosantacruz/auditanchor/merkle"
	"github.com/octaviosantacruz/auditanchor/ots"
)

func records(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(`{"seq":` + string(rune('0'+i%10)) + `,"event":"access"}`)
	}
	return out
}

func TestReceiptRoundTrip(t *testing.T) {
	recs := records(7)
	tree := merkle.New(recs)
	for i := range recs {
		r, err := New(tree, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := got.VerifyRecord(recs[i]); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if err := got.VerifyRecord(append(recs[i], ' ')); err == nil {
			t.Fatalf("record %d: accepted modified record", i)
		}
	}
}

// TestHeadBindsSize: the same audit path can verify for two sizes against one
// root (see merkle tests); the anchored digest differs, so the replay is caught.
func TestHeadBindsSize(t *testing.T) {
	tree := merkle.New(records(3))
	r, _ := New(tree, 0)
	d3, _ := r.Digest()
	r.TreeSize = 4
	if err := r.VerifyRecord(records(3)[0]); err != nil {
		t.Skip("path no longer verifies; nothing to replay")
	}
	d4, _ := r.Digest()
	if d3 == d4 {
		t.Fatal("head digest does not depend on tree size")
	}
}

func TestHeadDigestDomain(t *testing.T) {
	root := merkle.New(records(2)).Root()
	d := HeadDigest(2, root)
	if d == root || d == sha256.Sum256(root[:]) {
		t.Fatal("head digest is not domain-separated")
	}
	if HeadDigest(3, root) == d {
		t.Fatal("head digest ignores size")
	}
}

func TestDecodeRejects(t *testing.T) {
	tree := merkle.New(records(4))
	r, _ := New(tree, 1)
	good, _ := r.Encode()
	cases := map[string]string{
		"unknown field": strings.Replace(string(good), `"version": 1`, `"version": 1, "extra": true`, 1),
		"bad version":   strings.Replace(string(good), `"version": 1`, `"version": 2`, 1),
		"bad algorithm": strings.Replace(string(good), Algorithm, "sha1", 1),
		"index >= size": strings.Replace(string(good), `"leaf_index": 1`, `"leaf_index": 4`, 1),
		"trailing":      string(good) + "{}",
		"bad root":      strings.Replace(string(good), r.Root, "zz", 1),
	}
	for name, s := range cases {
		if _, err := Decode([]byte(s)); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
}

func TestTimestampAnchor(t *testing.T) {
	recs := records(5)
	tree := merkle.New(recs)
	r, _ := New(tree, 2)

	// A timestamp over the wrong message is refused.
	if err := r.SetTimestamp(ots.New([]byte("other"))); err == nil {
		t.Fatal("accepted timestamp over another message")
	}

	d, _ := r.Digest()
	ts := ots.New(d[:])
	n, err := ts.Add(ots.Append([]byte("nonce")))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := n.Add(ots.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	// Attach a synthetic Bitcoin attestation whose "Merkle root" is leaf.Msg,
	// and a header that contains it.
	leaf.Attestations = append(leaf.Attestations, ots.Attestation{Tag: ots.TagBitcoin, Payload: []byte{0x2a}}) // height 42
	if err := r.SetTimestamp(ts); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTimestamp(ts); err != nil || len(r.Anchors) != 1 {
		t.Fatalf("SetTimestamp should replace, anchors=%d err=%v", len(r.Anchors), err)
	}

	raw, _ := r.Encode()
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, ots.HeaderSize)
	copy(header[36:68], leaf.Msg)
	header[68] = 0x10 // block time
	res, err := got.Verify(context.Background(), recs[2], headers{42: header})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Anchored || res.Height != 42 || res.Time.Unix() != 0x10 {
		t.Fatalf("result = %+v", res)
	}

	// Offline: attestations listed, nothing claimed as verified.
	res, err = got.Verify(context.Background(), recs[2], nil)
	if err != nil || res.Anchored || len(res.Bitcoin) != 1 {
		t.Fatalf("offline result = %+v, %v", res, err)
	}

	// A header without the root must fail.
	bad := make([]byte, ots.HeaderSize)
	if _, err := got.Verify(context.Background(), recs[2], headers{42: bad}); err == nil {
		t.Fatal("verified against a header that does not contain the root")
	}

	// The exported .ots file parses with the reference format.
	file, err := got.DetachedOTS()
	if err != nil {
		t.Fatal(err)
	}
	df, err := ots.ParseDetached(file)
	if err != nil || !bytes.Equal(df.Digest, d[:]) {
		t.Fatalf("detached export: %v", err)
	}
}

type headers map[uint64][]byte

func (h headers) Header(_ context.Context, height uint64) ([]byte, error) {
	b, ok := h[height]
	if !ok {
		return nil, context.DeadlineExceeded
	}
	return b, nil
}

// TestRealPendingReceipt decodes a receipt stamped against the four public
// OpenTimestamps calendars on 2026-11-09 (real calendar responses).
func TestRealPendingReceipt(t *testing.T) {
	raw, err := os.ReadFile("../testdata/demo/receipt-pending.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile("../testdata/demo/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(log, []byte("\n")), []byte("\n"))
	res, err := r.Verify(context.Background(), lines[r.LeafIndex], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pending) != 4 || len(res.Bitcoin) != 0 || res.Anchored {
		t.Fatalf("result = %+v", res)
	}
	for _, u := range res.Pending {
		if !strings.HasPrefix(u, "https://") {
			t.Errorf("pending URI %q", u)
		}
	}
	if _, err := r.Verify(context.Background(), lines[0], nil); err == nil {
		t.Fatal("another line verified against this receipt")
	}
}
