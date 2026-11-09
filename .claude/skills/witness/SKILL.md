---
name: witness
description: >
  Enforces the tamper-evidence discipline this repo exists for: Merkle hashing
  stays RFC 6962 (domain-separated, no node duplication), anchors commit to the
  tree head including its size, untrusted proofs stay bounded and cannot steer
  network calls, and crypto primitives come from the standard library or
  golang.org/x/crypto, never hand-rolled. Use on ANY change to merkle/, ots/,
  receipt/ or cmd/auditanchor, and whenever the user says "witness" or asks to
  add a feature, fix a bug, or review code in this codebase.
license: MIT
---

# Witness

This library's only job is making tampering detectable after the fact. A
change that weakens that property is a regression even if every test passes
and the feature "works."

## Invariants that must never break

1. **RFC 6962 tree.** Leaves hash as `SHA-256(0x00 || data)`, nodes as
   `SHA-256(0x01 || l || r)`, split at the largest power of two below `n`.
   Never duplicate an unpaired node: that is CVE-2012-2459, and the original
   prototype of this repo had it (`TestNoDuplicationCollision` guards it).
2. **Anchors commit to (size, root).** An audit path alone does not bind the
   tree size. Anything anchored is `receipt.HeadDigest(size, root)`, never the
   bare root.
3. **Untrusted input stays bounded.** Receipts and `.ots` proofs come from
   outside. Keep the parser limits (message 4096, payload 8192, URI 1000, depth
   256, receipt/proof sizes) and strict decoding. `Upgrade` only contacts
   allowlisted calendars: a proof must never choose where we send requests.
4. **No hand-rolled primitives.** Hashes come from `crypto/*` or
   `golang.org/x/crypto` (RIPEMD-160 and Keccak only to read legacy proofs).
5. **Trust stays explicit.** Verification output must say what was checked and
   against what (own node vs Esplora). Never print "anchored" for a pending or
   unchecked attestation.

## Regression anchors

- `merkle`: Certificate Transparency vectors, exhaustive sizes 1–70 against a
  naive reference, fuzz targets.
- `ots`: `testdata/hello-world.txt.ots` must parse, re-serialize byte for byte
  and verify against the real header of block 358391; `FuzzParse` must stay
  stable (parse → serialize → parse).
- `receipt`: `testdata/demo/receipt-pending.json` holds real responses from the
  four public calendars.

## Output

Before touching `merkle/`, `ots/` or `receipt/`, say in one line which of the
invariants above the change could affect and how it preserves them.
