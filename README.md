# AuditAnchor

AuditAnchor is a tamper-evident audit log anchoring service written in Go. It receives audit events, stores them as NDJSON, builds a Merkle tree over canonical event records, and anchors the Merkle root through a pluggable backend.

The first backend is local file receipts for development. The intended next backend is OpenTimestamps, followed by optional Ethereum/Polygon testnet anchoring.

## Why This Exists

Normal audit logs can be rewritten by an attacker with admin access. AuditAnchor makes that detectable by periodically committing a Merkle root to an external timestamping layer. The raw logs stay private; only a hash root needs to leave your infrastructure.

## Relationship To MagicLink

MagicLink emits NDJSON audit events such as `created`, `viewed`, and later `expired_unseen`. AuditAnchor can ingest those events and anchor batches. The projects remain separate:

- MagicLink: secure one-time secret sharing.
- AuditAnchor: generic audit-log integrity for MagicLink or any other system.

## Crypto Learning Scope

This is a good cryptography project, but the right lesson is not to reimplement primitives like SHA-256 or AES for production. AuditAnchor uses Go's standard `crypto/sha256` and builds the protocol around it: domain-separated leaf/node hashing, Merkle roots, inclusion proofs, and receipt verification.

Good future crypto additions:

- Ed25519-signed receipts.
- Hash-chain checkpoints between batches.
- OpenTimestamps proof verification.
- Optional Ethereum smart contract for root anchoring.

## API

Append an event:

```http
POST /events
Content-Type: application/json

{
  "timestamp": "2026-08-02T00:00:00Z",
  "source": "magiclink",
  "event_id": "secret-123-created",
  "subject": "secret-123",
  "action": "created",
  "data": {"ttl_seconds": 900}
}
```

Anchor the current batch:

```http
POST /batches
```

Get an inclusion proof for event index `0`:

```http
GET /proof/0
```

## Local Run

Go is not installed on this machine right now, so this scaffold has not been compiled here yet.

```bash
go run ./cmd/server
```

Then:

```bash
curl -X POST http://localhost:8081/events \
  -H 'Content-Type: application/json' \
  --data @examples/magiclink-event.json

curl -X POST http://localhost:8081/batches
curl http://localhost:8081/proof/0
```

## Roadmap

- Add tests for Merkle root/proof verification.
- Add `auditanchor verify` CLI command.
- Add OpenTimestamps backend.
- Add signed receipts with Ed25519.
- Add MagicLink webhook/export integration.
- Add optional Ethereum/Polygon testnet backend.
