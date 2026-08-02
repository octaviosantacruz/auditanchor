# Design Notes

AuditAnchor stores canonical JSON event lines locally and hashes each line as a Merkle leaf. Leaf hashes are domain-separated with `0x00`; internal node hashes are domain-separated with `0x01`. This prevents a leaf hash from being confused with an internal node hash.

The service anchors the Merkle root, not the raw events. A verifier needs three things:

1. The original event record.
2. The Merkle proof returned by `/proof/{index}`.
3. The anchored root receipt.

If the record or any sibling hash changes, verification fails.

## MagicLink Integration Path

MagicLink can send every audit event to AuditAnchor via `POST /events`, or AuditAnchor can tail MagicLink's NDJSON audit log in a later version. The push API is easier for v0.1. Tailing is useful when MagicLink should remain fully decoupled and only write local audit files.
