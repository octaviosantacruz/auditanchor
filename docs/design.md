# Design notes

## Threat model

The adversary controls the host that produced the records, including its keys,
after the fact. AuditAnchor detects that the adversary changed, removed or
back-dated a record that was anchored before the compromise. It does not
prevent changes, it does not cover records that were never anchored, and it
does not prove a record is *true*, only that it existed unchanged since the
anchor time.

## Tree (package merkle)

RFC 6962 / RFC 9162 over SHA-256. Leaves are hashed with a `0x00` prefix and
nodes with `0x01`. A tree of `n` leaves splits at the largest power of two
below `n`. Inclusion and consistency proofs and their verification follow
RFC 9162 sections 2.1.3 and 2.1.4 literally; the tests use the Certificate
Transparency vectors and cross-check every size up to 70 against an
independent naive implementation.

The tree stores only leaf hashes. Callers choose the canonical byte form of a
record; for JSONL logs it is the line without its newline.

## Tree head

```
digest = SHA-256("auditanchor/tree-head/v1" || 0x00 || uint64be(size) || root)
```

The domain string makes the digest unlike any other SHA-256 value in the
system. The size is included because an audit path does not bind it: for
size 3 and size 4 the path of leaf 0 can be the same and verify against the
same root. Certificate Transparency solves this by signing (size, root); we
anchor (size, root).

## Anchors (package ots)

OpenTimestamps proofs are trees of operations (append, prepend, hashes) that
take the head digest to a Bitcoin block header's Merkle root. Stamping appends
a random 16-byte nonce and hashes before submitting, as the reference client
does, so calendars never learn the digest.

- `Stamp` submits to several calendars concurrently and requires two answers
  by default.
- `Upgrade` asks the calendars named in pending attestations for the completed
  proof. Only allowlisted calendars are contacted (SSRF protection).
- `VerifyHeader` compares the attested root with an 80-byte header. Getting the
  right header for a height is the one remaining trust decision: an own node,
  or an Esplora instance (whose header must hash to the block hash it reports).

Format support covers every op the reference implementation knows. RIPEMD-160
and Keccak-256 come from `golang.org/x/crypto` because the oldest proofs (the
reference `hello-world` example) use them; new proofs only use SHA-256.

## Receipt (package receipt)

JSON with the tree head, the leaf index, the audit path and anchors. Decoding is
strict (unknown fields, trailing data, oversized paths or proofs are errors).
Many receipts can share one anchor: stamp the head once, attach it to each.

## Consumers

Each project imports the module and keeps receipts next to its own data; there
is no AuditAnchor process, port or database. The project's existing scheduler
runs `Upgrade` until a Bitcoin attestation appears.

First consumer: Ozal's audit checkpoints (`ozal/internal/audit`), which are
signed but, per Ozal's own code, not evidence until retained off-host.
