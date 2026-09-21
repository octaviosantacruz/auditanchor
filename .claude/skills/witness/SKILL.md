---
name: witness
description: >
  Enforces the tamper-evidence discipline this repo exists for: logs are
  append-only, Merkle hashing must stay domain-separated, and crypto
  primitives come from the standard library, never hand-rolled. Use on ANY
  change to internal/merkle/, internal/store/, internal/api/, or anything
  touching event ingestion, batching, or receipt generation in this repo,
  and whenever the user says "witness" or asks to add a feature, fix a bug,
  or review code in this codebase. Do NOT use for unrelated tooling
  (Dockerfile, deploy scripts) unless it affects how events are persisted.
license: MIT
---

# Witness

This service's only job is making tampering detectable after the fact. A
change that weakens that property is a regression even if every test
passes and the feature "works."

## The two things that must never happen

1. **A stored event is mutated or deleted.** Raw NDJSON append-only storage
   is the whole point — the day something can rewrite `events.ndjson` in
   place, the anchoring is theater. Any code path that opens the event log
   for anything but append is wrong until proven otherwise.
2. **Merkle leaf/node hashing loses domain separation, or a primitive gets
   reimplemented.** This repo deliberately uses Go's stdlib `crypto/sha256`
   and builds the protocol (leaf hashing, node hashing, inclusion proofs)
   around it — per the README, that's the correct lesson, not a shortcut.
   Never write a custom hash/cipher "for learning" inside the actual
   ingestion or anchoring path; that belongs in `examples/` or a scratch
   file, clearly marked as non-production, if anywhere.

## Standing findings (2026-09-21 audit)

- This project runs natively with Go now (no longer Docker) — `./data/`
  holds `events.ndjson` / `receipts.ndjson` and is gitignored. Don't
  reintroduce a hardcoded `/data/...` path assuming a container filesystem.
- `POST /batches` (anchoring a Merkle root) and `GET /proof/{index}`
  (inclusion proof) were not exercised end-to-end in the audit — treat them
  as less-trusted than `/healthz` and `/events` until someone has actually
  walked the full anchor → proof → verify cycle.
- No tests exist yet for the Merkle tree construction itself — that's the
  single most important piece of logic in the repo to cover before trusting
  a refactor of it.

## Output

Before touching `internal/merkle/` or the event store, say in one line
whether the change preserves append-only-ness and domain separation. If a
change adds a new anchoring backend (OpenTimestamps, Ethereum/Polygon per
the roadmap), keep it behind the same pluggable interface the local-receipt
backend uses — don't special-case it into the ingestion path.
