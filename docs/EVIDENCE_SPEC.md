# Evidence

Guard records host observations, governance decisions, permit issuance, admitted effects, and effect outcomes as distinct events. Its journal records metadata and identifiers. It excludes the guest input document and request body.

Each workload has an independent sequence and hash chain. Hashes cover UTF-8 JSON with sorted keys, compact separators, and an empty current hash field. UTC uses Unix milliseconds. The host monotonic clock uses nanoseconds since the recorded boot ID. Authorization changes and admitted effects commit transactionally with required records.

```sh
alethic-guard evidence verify evidence.jsonl --write-checkpoint head.json
alethic-guard evidence verify evidence.jsonl --checkpoint retained-head.json
```

An unanchored local chain checks consistency only. Independently retain a checkpoint outside the Guard host to verify the covered prefix. Verification describes whether the checkpoint covers the head or only a prefix. An acknowledgment received through verified collector TLS and a receipt verified by an operator use different assurance values.
