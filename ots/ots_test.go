package ots

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Block 358391, fetched from Blockstream Esplora (hash
// 000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319).
const header358391 = "02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000" +
	"007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6"

const hash358391 = "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"

func helloWorld(t *testing.T) (*DetachedFile, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/hello-world.txt.ots")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDetached(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d, raw
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHelloWorldFixture uses the reference client's example proof.
func TestHelloWorldFixture(t *testing.T) {
	d, raw := helloWorld(t)
	content, err := os.ReadFile("../testdata/hello-world.txt")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if d.HashOp != OpSHA256 || !bytes.Equal(d.Digest, sum[:]) {
		t.Fatalf("digest %x does not match sha256 of hello-world.txt", d.Digest)
	}
	btc := d.Timestamp.Bitcoin()
	if len(btc) != 1 || btc[0].Height != 358391 {
		t.Fatalf("bitcoin attestations = %+v, want one at 358391", btc)
	}
	if got, want := btc[0].MerkleRootHex(), "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00"; got != want {
		t.Fatalf("merkle root = %s, want %s", got, want)
	}
	again, err := d.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, raw) {
		t.Fatal("parse/serialize does not round-trip byte for byte")
	}
}

func TestVerifyHeaderOffline(t *testing.T) {
	d, _ := helloWorld(t)
	header := mustHex(t, header358391)
	if BlockHash(header) != hash358391 {
		t.Fatalf("BlockHash = %s", BlockHash(header))
	}
	when, err := d.Timestamp.Bitcoin()[0].VerifyHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2015, 5, 28, 15, 41, 18, 0, time.UTC); !when.Equal(want) {
		t.Fatalf("block time = %s, want %s", when, want)
	}
	header[40] ^= 1
	if _, err := d.Timestamp.Bitcoin()[0].VerifyHeader(header); !errors.Is(err, ErrBitcoinMismatch) {
		t.Fatalf("tampered header: got %v, want ErrBitcoinMismatch", err)
	}
	if _, err := d.Timestamp.Bitcoin()[0].VerifyHeader(header[:79]); err == nil {
		t.Fatal("accepted short header")
	}
}

func TestTamperedProofFails(t *testing.T) {
	_, raw := helloWorld(t)
	content, _ := os.ReadFile("../testdata/hello-world.txt")
	header := mustHex(t, header358391)
	// Flipping any byte after the header either breaks parsing or moves the
	// attested Merkle root away from the real block: never a valid proof.
	for i := len(headerMagic) + 2; i < len(raw); i++ {
		bad := append([]byte(nil), raw...)
		bad[i] ^= 0x01
		if raw[i] == OpAppend || raw[i] == OpPrepend {
			// append<->prepend swap. Bitcoin's transaction tree duplicates the
			// last node of odd levels, so some siblings equal the message and
			// append X == prepend X there: the proof is unchanged, not forged.
			continue
		}
		d, err := ParseDetached(bad)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(content)
		if !bytes.Equal(d.Digest, sum[:]) {
			continue // proof is now about other content
		}
		for _, a := range d.Timestamp.Bitcoin() {
			if a.Height != 358391 {
				continue
			}
			if _, err := a.VerifyHeader(header); err == nil {
				t.Fatalf("byte %d flipped still verifies", i)
			}
		}
	}
}

type staticHeaders map[uint64][]byte

func (s staticHeaders) Header(_ context.Context, h uint64) ([]byte, error) {
	if b, ok := s[h]; ok {
		return b, nil
	}
	return nil, errors.New("unknown height")
}

func TestVerifyBitcoin(t *testing.T) {
	d, _ := helloWorld(t)
	when, height, err := VerifyBitcoin(context.Background(), d.Timestamp, staticHeaders{358391: mustHex(t, header358391)})
	if err != nil || height != 358391 || when.Year() != 2015 {
		t.Fatalf("VerifyBitcoin = %s %d %v", when, height, err)
	}
	if _, _, err := VerifyBitcoin(context.Background(), New([]byte("x")), staticHeaders{}); err == nil {
		t.Fatal("timestamp without attestations verified")
	}
}

func TestEsplora(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/block-height/358391":
			io.WriteString(w, hash358391)
		case "/block/" + hash358391 + "/header":
			io.WriteString(w, header358391)
		case "/block-height/1":
			io.WriteString(w, hash358391) // lies: header will not hash to it
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	e := Esplora{BaseURL: srv.URL}
	h, err := e.Header(context.Background(), 358391)
	if err != nil || hex.EncodeToString(h) != header358391 {
		t.Fatalf("Header = %x, %v", h, err)
	}
	if _, err := e.Header(context.Background(), 2); err == nil {
		t.Fatal("expected error for unknown height")
	}
}

func TestEsploraRejectsWrongHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/block-height/") {
			io.WriteString(w, strings.Repeat("ab", 32))
			return
		}
		io.WriteString(w, header358391)
	}))
	defer srv.Close()
	if _, err := (Esplora{BaseURL: srv.URL}).Header(context.Background(), 5); err == nil {
		t.Fatal("accepted a header that does not hash to the reported block")
	}
}

// fakeCalendar answers submissions with a pending attestation pointing at
// itself and, once confirmed, upgrades to a Bitcoin attestation at height 800000.
type fakeCalendar struct {
	srv       *httptest.Server
	confirmed atomic.Bool
	tail      []byte // calendar-specific append, so branches differ
}

func newFakeCalendar(t *testing.T, tail string) *fakeCalendar {
	fc := &fakeCalendar{tail: []byte(tail)}
	fc.srv = httptest.NewTLSServer(http.HandlerFunc(fc.serve))
	t.Cleanup(fc.srv.Close)
	return fc
}

func (fc *fakeCalendar) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Accept") != acceptHeader {
		http.Error(w, "bad accept", http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/digest":
		msg, _ := io.ReadAll(r.Body)
		ts := New(msg)
		n, _ := ts.Add(Append(fc.tail))
		c, _ := n.Add(SHA256())
		c.addAttestation(newPendingAttestation(fc.srv.URL))
		b, _ := ts.Serialize()
		w.Write(b)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/timestamp/"):
		if !fc.confirmed.Load() {
			http.NotFound(w, r)
			return
		}
		msg, err := hex.DecodeString(strings.TrimPrefix(r.URL.Path, "/timestamp/"))
		if err != nil {
			http.Error(w, "bad hex", http.StatusBadRequest)
			return
		}
		ts := New(msg)
		n, _ := ts.Add(Prepend([]byte("tx-prefix")))
		m, _ := n.Add(SHA256())
		m.addAttestation(newBitcoinAttestation(800000))
		b, _ := ts.Serialize()
		w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func TestStampAndUpgrade(t *testing.T) {
	a := newFakeCalendar(t, "cal-a")
	b := newFakeCalendar(t, "cal-b")
	client := &Client{
		HTTP:      a.srv.Client(), // both test servers share the httptest CA
		Calendars: []string{a.srv.URL, b.srv.URL},
		Allowlist: []string{a.srv.URL, b.srv.URL},
	}
	digest := bytes.Repeat([]byte{0x42}, 32)
	ts, err := client.Stamp(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ts.Msg, digest) {
		t.Fatal("timestamp not rooted at digest")
	}
	if p := ts.Pending(); len(p) != 2 {
		t.Fatalf("pending = %v, want 2 calendars", p)
	}

	// The proof must survive serialization (this is what gets stored).
	raw, err := ts.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ts, err = Parse(digest, raw)
	if err != nil {
		t.Fatal(err)
	}

	res := client.Upgrade(context.Background(), ts)
	if len(res.Pending) != 2 || len(res.Upgraded) != 0 || len(res.Errors) != 0 {
		t.Fatalf("before confirmation: %+v", res)
	}
	a.confirmed.Store(true)
	res = client.Upgrade(context.Background(), ts)
	if len(res.Upgraded) != 1 || len(res.Pending) != 1 {
		t.Fatalf("after confirming a: %+v", res)
	}
	btc := ts.Bitcoin()
	if len(btc) != 1 || btc[0].Height != 800000 {
		t.Fatalf("bitcoin attestations = %+v", btc)
	}
	if _, err := ts.Serialize(); err != nil {
		t.Fatal(err)
	}
}

func TestStampNeedsMinResponses(t *testing.T) {
	a := newFakeCalendar(t, "cal-a")
	client := &Client{
		HTTP:      a.srv.Client(),
		Calendars: []string{a.srv.URL, "https://127.0.0.1:1"},
	}
	if _, err := client.Stamp(context.Background(), make([]byte, 32)); err == nil {
		t.Fatal("stamp succeeded with 1 of 2 required calendars")
	}
	client.MinResponses = 1
	if _, err := client.Stamp(context.Background(), make([]byte, 32)); err != nil {
		t.Fatalf("stamp with MinResponses=1: %v", err)
	}
}

func TestUpgradeSkipsUnlistedCalendars(t *testing.T) {
	a := newFakeCalendar(t, "cal-a")
	client := &Client{HTTP: a.srv.Client(), Calendars: []string{a.srv.URL}, Allowlist: []string{a.srv.URL}}
	ts, err := client.Stamp(context.Background(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	a.confirmed.Store(true)
	client.Allowlist = nil // defaults: public calendars only
	res := client.Upgrade(context.Background(), ts)
	if len(res.Skipped) != 1 || len(res.Upgraded) != 0 {
		t.Fatalf("expected the test calendar to be skipped: %+v", res)
	}
}

func TestAllowlist(t *testing.T) {
	cases := map[string]bool{
		"https://alice.btc.calendar.opentimestamps.org":     true,
		"https://bob.btc.calendar.opentimestamps.org/":      true,
		"https://finney.calendar.eternitywall.com":          true,
		"https://btc.calendar.catallaxy.com":                true,
		"http://alice.btc.calendar.opentimestamps.org":      false,
		"https://evil.example.com":                          false,
		"https://calendar.opentimestamps.org":               false, // wildcard needs a label
		"https://a.b.btc.calendar.opentimestamps.org":       false, // wildcard is one label
		"https://alice.btc.calendar.opentimestamps.org:444": false,
		"https://alice.btc.calendar.opentimestamps.org/x":   false,
		"https://x@alice.btc.calendar.opentimestamps.org":   false,
	}
	for uri, want := range cases {
		if got := allowed(uri, DefaultUpgradeAllowlist); got != want {
			t.Errorf("allowed(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestMalformedInputs(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"unknown op":       {0x55},
		"truncated append": {OpAppend, 0x05, 0x01},
		"zero-length arg":  {OpAppend, 0x00},
		"trailing bytes":   append(append([]byte{0x00}, newBitcoinAttestation(1).appendTo(nil)...), 0x00),
		"bad pending uri":  append([]byte{0x00}, Attestation{Tag: TagPending, Payload: appendVarbytes(nil, []byte("https://x/?a=b"))}.appendTo(nil)...),
		"varuint overflow": {0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
	}
	for name, data := range cases {
		if _, err := Parse([]byte("msg"), data); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
	deep := bytes.Repeat([]byte{OpSHA256}, maxDepth+2)
	deep = append(deep, append([]byte{0x00}, newBitcoinAttestation(1).appendTo(nil)...)...)
	if _, err := Parse([]byte("msg"), deep); err == nil {
		t.Error("accepted nesting beyond maxDepth")
	}
	if _, err := ParseDetached([]byte("not an ots file")); err == nil {
		t.Error("ParseDetached accepted garbage")
	}
}

func FuzzParse(f *testing.F) {
	raw, err := os.ReadFile("../testdata/hello-world.txt.ots")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := ParseDetached(data)
		if err != nil {
			return
		}
		out, err := d.Serialize()
		if err != nil {
			t.Fatalf("parsed proof does not serialize: %v", err)
		}
		d2, err := ParseDetached(out)
		if err != nil {
			t.Fatalf("serialized proof does not parse: %v", err)
		}
		out2, err := d2.Serialize()
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatal("serialization is not stable")
		}
	})
}
