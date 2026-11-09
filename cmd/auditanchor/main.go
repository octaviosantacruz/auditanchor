// Command auditanchor builds, anchors and verifies AuditAnchor receipts.
//
//	auditanchor root    -lines FILE
//	auditanchor prove   -lines FILE -index N [-o receipt.json]
//	auditanchor stamp   [-calendar URL]... [-min N] receipt.json
//	auditanchor upgrade receipt.json
//	auditanchor verify  (-record FILE | -lines FILE) [-esplora URL] receipt.json
//	auditanchor info    receipt.json
//	auditanchor export-ots -o head.ots receipt.json
//
// With -lines, each line of FILE (without its trailing newline) is one record,
// which matches JSONL/NDJSON audit logs such as Ozal's.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/octaviosantacruz/auditanchor/merkle"
	"github.com/octaviosantacruz/auditanchor/ots"
	"github.com/octaviosantacruz/auditanchor/receipt"
)

const usage = `usage: auditanchor <command> [flags]

commands:
  root       print size, root and head digest of a JSONL file
  prove      write a receipt for one line of a JSONL file
  stamp      anchor a receipt's head with OpenTimestamps calendars
  upgrade    fetch completed (Bitcoin) proofs for pending anchors
  verify     check a record against a receipt and its anchors
  info       describe a receipt
  export-ots write the anchor as a .ots file for the reference client

Run "auditanchor <command> -h" for flags.
`

// errFailed marks a verification failure (exit 1) already reported.
var errFailed = errors.New("verification failed")

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmds := map[string]func(context.Context, []string) error{
		"root":       cmdRoot,
		"prove":      cmdProve,
		"stamp":      cmdStamp,
		"upgrade":    cmdUpgrade,
		"verify":     cmdVerify,
		"info":       cmdInfo,
		"export-ots": cmdExport,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		if os.Args[1] == "-h" || os.Args[1] == "help" || os.Args[1] == "--help" {
			fmt.Print(usage)
			return
		}
		fmt.Fprintf(os.Stderr, "auditanchor: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err := cmd(ctx, os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(os.Stderr, "auditanchor:", err)
			os.Exit(2)
		}
		if !errors.Is(err, errFailed) {
			fmt.Fprintln(os.Stderr, "auditanchor:", err)
		}
		os.Exit(1)
	}
}

type usageError string

func (e usageError) Error() string { return string(e) }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// parse parses flags and returns the positional arguments, allowing flags to
// appear after them (as in "verify receipt.json -record r.json").
func parse(fs *flag.FlagSet, args []string, positional int) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) != positional {
		return nil, usageError(fmt.Sprintf("%s: expected %d argument(s), got %d", fs.Name(), positional, len(pos)))
	}
	return pos, nil
}

func readLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	r := bufio.NewReaderSize(f, 1<<16)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return nil, fmt.Errorf("%s: last line has no trailing newline (incomplete record?)", path)
			}
			out = append(out, line[:len(line)-1])
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func cmdRoot(_ context.Context, args []string) error {
	fs := newFlags("root")
	lines := fs.String("lines", "", "JSONL file: one record per line")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if *lines == "" {
		return usageError("root: -lines is required")
	}
	recs, err := readLines(*lines)
	if err != nil {
		return err
	}
	tree := merkle.New(recs)
	fmt.Printf("size   %d\nroot   %s\ndigest %s\n", tree.Size(), tree.Root(), receipt.HeadDigest(tree.Size(), tree.Root()))
	return nil
}

func cmdProve(_ context.Context, args []string) error {
	fs := newFlags("prove")
	lines := fs.String("lines", "", "JSONL file: one record per line")
	index := fs.Uint64("index", 0, "zero-based line to prove")
	out := fs.String("o", "", "write the receipt here (default stdout)")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if *lines == "" {
		return usageError("prove: -lines is required")
	}
	recs, err := readLines(*lines)
	if err != nil {
		return err
	}
	r, err := receipt.New(merkle.New(recs), *index)
	if err != nil {
		return err
	}
	b, err := r.Encode()
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return writeAtomic(*out, b)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdStamp(ctx context.Context, args []string) error {
	fs := newFlags("stamp")
	var cals multiFlag
	fs.Var(&cals, "calendar", "calendar URL (repeatable; default: public calendars)")
	min := fs.Int("min", 0, "calendars that must answer (default 2)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	r, err := loadReceipt(pos[0])
	if err != nil {
		return err
	}
	d, err := r.Digest()
	if err != nil {
		return err
	}
	client := &ots.Client{MinResponses: *min}
	if len(cals) > 0 {
		client.Calendars = cals
		client.Allowlist = append(append([]string(nil), ots.DefaultUpgradeAllowlist...), cals...)
	}
	ts, err := client.Stamp(ctx, d[:])
	if err != nil {
		return err
	}
	if old, err := r.Timestamp(); err == nil && old != nil {
		if err := ts.Merge(old); err != nil {
			return err
		}
	}
	if err := r.SetTimestamp(ts); err != nil {
		return err
	}
	if err := saveReceipt(pos[0], r); err != nil {
		return err
	}
	fmt.Printf("stamped head %s\npending at:\n", d)
	for _, u := range ts.Pending() {
		fmt.Println("  " + u)
	}
	fmt.Println("run \"auditanchor upgrade\" in a few hours to fetch the Bitcoin confirmation")
	return nil
}

func cmdUpgrade(ctx context.Context, args []string) error {
	fs := newFlags("upgrade")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	r, err := loadReceipt(pos[0])
	if err != nil {
		return err
	}
	ts, err := r.Timestamp()
	if err != nil {
		return err
	}
	if ts == nil {
		return errors.New("receipt has no OpenTimestamps anchor; run \"auditanchor stamp\" first")
	}
	res := (&ots.Client{}).Upgrade(ctx, ts)
	for _, u := range res.Upgraded {
		fmt.Println("upgraded from", u)
	}
	for _, u := range res.Pending {
		fmt.Println("still pending at", u)
	}
	for _, u := range res.Skipped {
		fmt.Println("skipped (not in allowlist)", u)
	}
	for _, e := range res.Errors {
		fmt.Fprintln(os.Stderr, "error:", e)
	}
	if len(res.Upgraded) > 0 {
		if err := r.SetTimestamp(ts); err != nil {
			return err
		}
		if err := saveReceipt(pos[0], r); err != nil {
			return err
		}
	}
	for _, a := range ts.Bitcoin() {
		fmt.Printf("bitcoin block %d, merkle root %s\n", a.Height, a.MerkleRootHex())
	}
	if len(res.Errors) > 0 && len(res.Upgraded) == 0 && len(res.Pending) == 0 {
		return errFailed
	}
	return nil
}

func cmdVerify(ctx context.Context, args []string) error {
	fs := newFlags("verify")
	recordPath := fs.String("record", "", "file holding exactly the record bytes")
	lines := fs.String("lines", "", "JSONL file; the record is the line at the receipt's leaf_index")
	esplora := fs.String("esplora", "", "check Bitcoin headers via this Esplora API (e.g. https://blockstream.info/api)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if (*recordPath == "") == (*lines == "") {
		return usageError("verify: give exactly one of -record or -lines")
	}
	r, err := loadReceipt(pos[0])
	if err != nil {
		return err
	}
	var record []byte
	if *recordPath != "" {
		if record, err = os.ReadFile(*recordPath); err != nil {
			return err
		}
	} else {
		recs, err := readLines(*lines)
		if err != nil {
			return err
		}
		if r.LeafIndex >= uint64(len(recs)) {
			return fmt.Errorf("%s has %d lines; receipt is for line %d", *lines, len(recs), r.LeafIndex)
		}
		record = recs[r.LeafIndex]
	}
	var src ots.HeaderSource
	if *esplora != "" {
		src = ots.Esplora{BaseURL: *esplora}
	}
	res, err := r.Verify(ctx, record, src)
	if err != nil {
		if errors.Is(err, merkle.ErrInvalidProof) {
			fmt.Println("FAIL: record is not in this tree head:", err)
			return errFailed
		}
		if errors.Is(err, ots.ErrBitcoinMismatch) {
			fmt.Println("FAIL:", err)
			return errFailed
		}
		return err
	}
	fmt.Printf("OK   record is leaf %d of %d under root %s\n", res.LeafIndex, res.TreeSize, res.Root)
	fmt.Printf("     head digest %s\n", res.Digest)
	switch {
	case res.Anchored:
		fmt.Printf("OK   anchored in Bitcoin block %d at %s (headers from %s)\n", res.Height, res.Time.Format(time.RFC3339), *esplora)
	case len(res.Bitcoin) > 0:
		fmt.Println("--   Bitcoin attestations (not checked; no -esplora). Compare with your own node:")
		for _, a := range res.Bitcoin {
			fmt.Printf("     block %d must have merkle root %s\n", a.Height, a.MerkleRootHex())
			fmt.Printf("       bitcoin-cli getblockheader $(bitcoin-cli getblockhash %d) | grep merkleroot\n", a.Height)
		}
	case len(res.Pending) > 0:
		fmt.Println("--   anchor pending at:", strings.Join(res.Pending, ", "))
		fmt.Println("     run \"auditanchor upgrade\" later; until then the time is not proven")
	default:
		fmt.Println("--   no anchor: inclusion is proven, time is not")
	}
	return nil
}

func cmdInfo(_ context.Context, args []string) error {
	fs := newFlags("info")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	r, err := loadReceipt(pos[0])
	if err != nil {
		return err
	}
	d, _ := r.Digest()
	fmt.Printf("leaf   %d of %d\nroot   %s\ndigest %s\npath   %d hashes\n", r.LeafIndex, r.TreeSize, r.Root, d, len(r.Path))
	ts, err := r.Timestamp()
	if err != nil {
		return err
	}
	if ts == nil {
		fmt.Println("anchor none")
		return nil
	}
	for _, f := range ts.All() {
		fmt.Printf("anchor %s\n", f.Attestation)
	}
	return nil
}

func cmdExport(_ context.Context, args []string) error {
	fs := newFlags("export-ots")
	out := fs.String("o", "", "output .ots file")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if *out == "" {
		return usageError("export-ots: -o is required")
	}
	r, err := loadReceipt(pos[0])
	if err != nil {
		return err
	}
	b, err := r.DetachedOTS()
	if err != nil {
		return err
	}
	if err := writeAtomic(*out, b); err != nil {
		return err
	}
	d, _ := r.Digest()
	fmt.Printf("wrote %s\nreference client: ots verify -d %s %s\n", *out, d, *out)
	return nil
}

func loadReceipt(path string) (*receipt.Receipt, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return receipt.Decode(b)
}

func saveReceipt(path string, r *receipt.Receipt) error {
	b, err := r.Encode()
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

// writeAtomic replaces path without ever leaving a truncated file behind.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".auditanchor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
