package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	os.WriteFile(good, []byte("{\"a\":1}\n\n{\"b\":2}\n"), 0o600)
	recs, err := readLines(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || string(recs[0]) != `{"a":1}` || len(recs[1]) != 0 {
		t.Fatalf("records = %q", recs)
	}
	torn := filepath.Join(dir, "torn.jsonl")
	os.WriteFile(torn, []byte("{\"a\":1}\n{\"b\""), 0o600)
	if _, err := readLines(torn); err == nil {
		t.Fatal("accepted a file whose last record is incomplete")
	}
}

func TestWriteAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.json")
	if err := writeAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	entries, _ := os.ReadDir(filepath.Dir(p))
	if string(b) != "two" || len(entries) != 1 {
		t.Fatalf("content %q, %d entries", b, len(entries))
	}
}
