# AuditAnchor

AuditAnchor is the shared integrity layer for the Ozal, SIGEA and Custodia
projects. It lets a third party check that a record existed at a given time and
has not been rewritten since, without trusting the server that produced it.

It is a Go library plus a CLI. A project batches its records into an RFC 6962
Merkle tree, anchors the tree head on Bitcoin through OpenTimestamps, and hands
out receipts that anyone can verify offline. The raw records stay private: only
a hash leaves your infrastructure.

> Status: milestone 1 in progress. The library and CLI work, including real
> stamps against the public OpenTimestamps calendars and a real Ozal audit
> checkpoint anchored on 2026-11-09. Still missing: its Bitcoin confirmation
> verified from another machine. See
> [STATUSCHECK.md](STATUSCHECK.md).

## Why This Exists

An audit log can be rewritten by anyone with admin access to the host. Hash
chains and signed checkpoints detect edits *within* the retained files, but they
cannot prove that the operator did not rewrite the whole log and re-sign it.
That requires evidence kept outside the host's control.

Each project already promises evidence and lacks exactly that:

- **Ozal** explains every access decision. Its audit log is hash-chained with
  Ed25519 checkpoints, but those checkpoints only become evidence once they are
  retained off-host. AuditAnchor is that off-host anchor.
- **SIGEA** puts evidence behind every vulnerability. Anchoring makes that
  evidence dated and immutable: a finding provably existed on a given date.
- **Custodia** correlates security tools. Anchoring gives its conclusions an
  integrity proof.

## What This Is Not

- **Not a generic anchoring service.** Sigstore Rekor, Trillian, immudb and
  OpenTimestamps already cover that space; AuditAnchor exists to serve these
  three projects. There is no server to run.
- **Not a blockchain project.** Anchoring a hash on Bitcoin is applied
  cryptography (Merkle trees, inclusion proofs, timestamps), not blockchain
  development. There is no token, wallet or smart contract.
- **Not a reimplementation of primitives.** Hashes come from Go's standard
  library, plus `golang.org/x/crypto` for the two legacy hashes the
  OpenTimestamps format still contains (RIPEMD-160, Keccak-256).

## Packages

```text
github.com/octaviosantacruz/auditanchor
  merkle/          RFC 6962 tree: roots, inclusion and consistency proofs
  ots/             OpenTimestamps: parse/serialize, stamp, upgrade, Bitcoin check
  receipt/         portable receipt: tree head + inclusion proof + anchors
  cmd/auditanchor  CLI: root, prove, stamp, upgrade, verify, info, export-ots
```

### From Go

```go
tree := merkle.New(records)               // records are exact bytes, e.g. JSONL lines

// Anchor the tree head once. The digest commits to size and root together.
head := receipt.HeadDigest(tree.Size(), tree.Root())
ts, err := (&ots.Client{}).Stamp(ctx, head[:]) // pending until Bitcoin confirms

// Later, from the project's own periodic job (confirmation takes hours):
res := (&ots.Client{}).Upgrade(ctx, ts)

// One receipt per record you need to prove; they all share the anchor.
r, err := receipt.New(tree, index)
err = r.SetTimestamp(ts)
b, err := r.Encode()                        // JSON, hand it to an auditor
```

Verification needs only the record and the receipt:

```go
r, err := receipt.Decode(b)
res, err := r.Verify(ctx, record, ots.Esplora{BaseURL: "https://blockstream.info/api"})
// res.Anchored, res.Height, res.Time
```

Pass `nil` instead of a header source to verify offline; the result then lists
the Bitcoin block heights and Merkle roots to compare against your own node.

`merkle.Tree.ConsistencyProof` and `merkle.VerifyConsistency` prove that a
later tree head only appended to an earlier one, so successive anchors of a
growing log show that the past was not rewritten.

### From the CLI

```bash
go install github.com/octaviosantacruz/auditanchor/cmd/auditanchor@latest

auditanchor root  -lines audit.jsonl                 # size, root, head digest
auditanchor prove -lines audit.jsonl -index 1 -o receipt.json
auditanchor stamp receipt.json                       # submit to public calendars
auditanchor upgrade receipt.json                     # a few hours later
auditanchor verify receipt.json -lines audit.jsonl   # offline
auditanchor verify receipt.json -lines audit.jsonl -esplora https://blockstream.info/api
auditanchor export-ots -o head.ots receipt.json      # for the reference "ots" client
```

With `-lines`, each line of the file without its trailing newline is one record.
A file whose last line has no newline is rejected as a possibly torn write.

### Anchoring Ozal audit checkpoints

Ozal signs checkpoints of its hash-chained audit log, and says itself that
they prove nothing until a copy is kept outside the host. Anchor them:

```bash
ozal audit checkpoint -key file:/etc/ozal/audit.key -out /tmp/ckpt.json -config edge.json
cat /tmp/ckpt.json >> checkpoints.jsonl          # one checkpoint per line
auditanchor prove -lines checkpoints.jsonl -index N -o ckpt-N.json
auditanchor stamp ckpt-N.json                    # later: auditanchor upgrade
```

An auditor then checks, from anywhere: the chain against the checkpoint
(`ozal audit verify -checkpoint ... -public-key ...`), and the checkpoint
against the anchor (`auditanchor verify ckpt-N.json -lines checkpoints.jsonl`).
Use `-lines` here: `-record` hashes a file byte for byte, including its final
newline. `testdata/ozal/` holds a real example, anchored on 2026-11-09.

## Design

```text
records (Ozal checkpoints, SIGEA evidence, ...)
  -> leaf hash     SHA-256(0x00 || record)
  -> node hash     SHA-256(0x01 || left || right), RFC 6962 split
  -> head digest   SHA-256("auditanchor/tree-head/v1" || 0x00 || uint64be(size) || root)
  -> OpenTimestamps: append nonce, SHA-256, submit to calendars
  -> Bitcoin block header Merkle root (after confirmation)
```

Choices that matter for security:

- **RFC 6962 split, no duplication.** An unpaired node is promoted, never
  copied. Duplicating it (as Bitcoin's transaction tree does) lets `[a,b,c]`
  and `[a,b,c,c]` share a root (CVE-2012-2459). The prototype had that bug.
- **The anchor covers size and root.** An audit path alone does not bind the
  tree size: the same path can verify for two sizes against one root. The head
  digest includes the size, so a receipt cannot be replayed against another.
- **Untrusted proofs cannot make the verifier call arbitrary URLs.** `Upgrade`
  only contacts calendars on an allowlist (public OpenTimestamps calendars by
  default), so a hostile receipt cannot be used for SSRF.
- **Bounded parsing.** Message, argument, payload and nesting limits follow the
  reference implementation; the parser is fuzzed and round-trips the reference
  example proof byte for byte.
- **Trust is explicit.** `-esplora` trusts that service for the
  height-to-block mapping (the header must still hash to the block it names).
  Offline verification prints the block and root to check with `bitcoin-cli`.

More detail in [docs/design.md](docs/design.md).

## Development

```bash
go test -race ./...
go test ./merkle -run=^$ -fuzz=FuzzVerifyInclusion -fuzztime=30s
go test ./ots    -run=^$ -fuzz=FuzzParse           -fuzztime=30s
```

Test vectors: Certificate Transparency roots and proofs for the tree; the
OpenTimestamps reference `hello-world.txt.ots` (Bitcoin block 358391) and its
real block header for the anchor; a receipt stamped against the four public
calendars on 2026-11-09 for real calendar responses.

## License

MIT
