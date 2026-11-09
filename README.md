# AuditAnchor

AuditAnchor is the shared integrity layer for the Ozal, SIGEA and Custodia
projects. It lets a third party check that a record existed at a given time and
has not been rewritten since, without trusting the server that produced it.

It batches records into a Merkle tree, anchors the root on an external
timestamping layer, and hands out inclusion proofs that can be verified offline.
The raw records stay private: only a hash root leaves your infrastructure.

> Status: early prototype. See [STATUSCHECK.md](STATUSCHECK.md) for the real
> state of the code and the milestone that decides whether the idea holds.

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
  three projects.
- **Not a blockchain project.** Anchoring a hash on Bitcoin is applied
  cryptography (Merkle trees, inclusion proofs, timestamps), not blockchain
  development. There is no token, wallet or smart contract.
- **Not a reimplementation of primitives.** It uses Go's standard
  `crypto/sha256` and builds the protocol around it.

## Design

```text
records (Ozal checkpoints, SIGEA evidence, ...)
  -> domain-separated leaf hashes (0x00 || record)
  -> Merkle tree, interior nodes 0x01 || left || right
  -> root anchored externally (OpenTimestamps -> Bitcoin)
  -> inclusion proof per record, verifiable offline
```

The tree is being moved to the RFC 6962 shape: an unpaired node is promoted, not
duplicated. Duplicating the last node (as Bitcoin does) lets `[a,b,c]` and
`[a,b,c,c]` share a root (CVE-2012-2459).

## Shape: a Go library plus a CLI

AuditAnchor is a Go module the three projects import, not a service they call.
Each project builds trees over its own records and stores receipts next to its
own data, so there is no extra process, port, disk or backup to operate.

```text
github.com/octaviosantacruz/auditanchor
  merkle/          RFC 6962 tree, inclusion proofs, Verify
  ots/             stamp and upgrade with OpenTimestamps
  proof/           portable receipt: root + inclusion proof + OTS stamp
  cmd/auditanchor  CLI: verify (plus stamp/upgrade for manual operation)
```

Intended use from a consumer:

```go
tree := merkle.New(records)
stamp, err := ots.Stamp(ctx, tree.Root())      // pending until Bitcoin confirms
// later, from the consumer's own periodic job:
stamp, err = ots.Upgrade(ctx, stamp)
receipt := proof.New(tree, index, stamp)       // hand this to an auditor
```

```bash
auditanchor verify receipt.json record.json    # offline, trusts no server
```

OpenTimestamps stamps start pending and are confirmed on Bitcoin hours later.
The library provides `Upgrade`; each consumer calls it from the scheduler it
already has.

> The code today is still the original prototype: an HTTP server
> (`cmd/server`, `internal/api`, `internal/eventlog`) and a local-file anchor
> (`internal/anchor`). Those are slated for removal; only `internal/merkle`
> carries over, promoted to `merkle/`. The API above is the target, not what
> exists yet.

## Roadmap

Milestone 1, which decides whether the idea holds:

1. RFC 6962 tree, root/proof tests against known vectors, fuzzing of
   `Proof`/`Verify`.
2. `auditanchor verify`: offline verification that does not trust the server.
3. OpenTimestamps backend; anchor a real Ozal checkpoint and verify it from
   another machine.

Milestone 1 also does the reshape: promote `merkle/`, add `ots/`, `proof/` and
`cmd/auditanchor`, and drop the HTTP server and file anchor.

After that, if third-party verification holds up:

- Ozal as the first consumer: periodic anchoring of audit checkpoints.
- SIGEA scan evidence.
- Ed25519-signed receipts and hash-chain checkpoints between batches.
