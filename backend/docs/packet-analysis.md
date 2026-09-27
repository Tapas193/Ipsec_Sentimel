# Packet Analysis — IPsec Sentinel (Phase 2)

This document describes how uploaded captures are parsed and analyzed. Everything
reported by the backend is **derived from real parsed packets** — no values are
fabricated, and anything that cannot be decoded is reported as `unknown`.

## 1. Pipeline

```
upload → validate → store (SHA-256, generated filename) → analyze job:
    VALIDATION → PACKET_READING → PROTOCOL_DETECTION → IKE_ANALYSIS
    → ESP_ANALYSIS → FLOW_BUILDING → FEATURE_EXTRACTION → PERSISTENCE
```

Job stages are tracked on `analysis_jobs.progress` (0.0 → 1.0); the frontend
polls the analysis detail endpoint while `status == running`.

## 2. Capture ingestion

- **Validation** (`app/services/capture_store.py`):
  - extension allow-list `.pcap | .cap | .pcapng`
  - magic-byte check for pcap (little/big endian & nanosecond variants) and pcapng
  - non-empty, `MAX_UPLOAD_SIZE_MB` limit
  - filename must not contain path separators
- **Integrity**: SHA-256 over the exact uploaded bytes; stored in `captures.sha256`.
- **Storage**: written under `UPLOAD_DIR` under a generated name
  (`CAP-000001.pcap`), never the user filename, via atomic temp-then-rename.
- Malformed / unsupported content is rejected as `UNSUPPORTED_FORMAT`; a file with
  valid magic but corrupt packet data is stored and parsed defensively at analysis
  time (0 packets, no crash).

## 3. Packet readers

`app/analyzers/packet_analyzer/reader.py` provides two readers and one builtin:

| Reader | Name | Notes |
| --- | --- | --- |
| TShark | `tshark` | subprocess `tshark -r … -T json -x`, argument list only (no `shell=True`), 120s timeout |
| Scapy | `scapy` | `rdpcap`, pure-Python fallback |
| Builtin | `builtin` | dependency-free pcap/pcapng reader; always available |

The active reader is auto-detected (first installed in order `tshark → scapy →
builtin`) and reported by `GET /api/v1/system/tools`. The same frames are passed
through the identical parser regardless of reader.

## 4. Parser

`app/analyzers/packet_analyzer/parser.py` decodes raw frame bytes with a
dependency-free parser (`app/analyzers/packet_analyzer/protocols/*`):

- Ethernet, VLAN, IPv4, IPv6
- UDP/TCP with port-based dispatch to IKE (500) and NAT-T (4500)
- ESP (Encapsulating Security Payload), including ESP-over-4500 where the UDP
  payload begins directly with the ESP header. The 4-byte zero prefix is the
  non-ESP marker and is *not* the ESP header.
- AH (Authentication Header)
- IKEv1/v2 header, payload chain (SA, Proposal, Transform, KE, Nonce, IDs, …)

Representative packet metadata (source/destination, ports, protocols, timestamps,
lengths) feeds flow building; parsed IKE/ESP/AH records feed the analysis models.

## 5. Protocol detection

`app/analyzers/packet_analyzer/protocol_detector.py` decides whether the capture is
IPsec traffic:

- `protocol_detected` = `yes` / `no`
- `protocol_confidence` = `low | medium | high`
- per-protocol booleans: `ike_detected`, `esp_detected`, `ah_detected`
- IP version booleans: `ipv4_detected`, `ipv6_detected`
- observations list: packet/byte counts, first/last seen, confidence per protocol

Confidence is derived from evidence (counts, exchange completeness, SPI reuse).

## 6. IKE analysis

`app/analyzers/packet_analyzer/base.py` / engine extract per-message records:

- version (1/2), exchange name/type, flags, message id, SPI pair (initiator/responder)
- source/destination + ports, direction (`m->r` initiator, `r->m` responder —
  responder flag bit `0x20`, initiator bit `0x01`)
- proposal/transform table: protocol id, encryption + key length, integrity, PRF,
  DH group, ESN, transform confidence

**Honesty note**: proposal *status* is `OFFERED` for initiator proposals and
`SELECTED` for responder proposals — this is a documented inference from
direction, not a decrypted product. `encryption_algorithm` is reported as
`UNKNOWN` wherever the transform id cannot be decoded.

## 7. ESP & AH records

- SPI, sequence number, direction, length
- `encryption_algorithm` — best-effort decode from the transform table (Phase 2
  reports matches from valid IKE SA proposals); otherwise `UNKNOWN`.
- Decryption is **never** attempted; payload content is not inspected beyond
  header fields because keys are not available. This is a stated Phase 2 limit.

## 8. Flow building

`app/analyzers/packet_analyzer/flow_builder.py` groups packets into bidirectional
flows keyed by `(ip version, src ip, dst ip, protocol, ports)`, tracking
upstream/downstream counts & bytes, duration, SPI lineage, and IKE/ESP/AH packet
counts per flow. Flow direction (`up`/`down`/`both`) reflects observed directions.

## 9. Feature extraction

`app/analyzers/packet_analyzer/feature_extractor.py` computes descriptive
statistics per flow: packet/byte counts, rates, packet-size statistics
(mean/median/std/min/max/quartiles), interarrival statistics, direction ratio,
burst statistics (100 ms window), and a packet-size histogram. Each value conforms
to `configs/feature_schema.yaml`.

## 10. Persistence

Analysis results persist to PostgreSQL (or SQLite for tests) via
`app/services/analysis_service.py` into `analyses`, `protocol_observations`,
`ike_messages`, `ike_proposals`, `esp_packets`, `ah_packets`, `flows`,
`flow_features`. `persists` are transactional with the job's `PERSISTENCE` stage.

## 11. API surface (Phase 2)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/captures` | upload + validate + SHA-256 |
| `POST` | `/api/v1/captures/{key}/analyze` | start analysis job |
| `GET` | `/api/v1/captures/{key}` | capture detail |
| `DELETE` | `/api/v1/captures/{key}` | delete capture + file |
| `GET` | `/api/v1/analysis-jobs` | job list (paginated) |
| `GET` | `/api/v1/analyses` | analysis list (paginated) |
| `GET` | `/api/v1/analyses/{key}` | summary + job state |
| `GET` | `/api/v1/analyses/{key}/protocol-observations` | observations |
| `GET` | `/api/v1/analyses/{key}/ike-messages` | IKE messages (+ proposals) |
| `GET` | `/api/v1/analyses/{key}/esp-packets` | ESP records |
| `GET` | `/api/v1/analyses/{key}/ah-packets` | AH records |
| `GET` | `/api/v1/analyses/{key}/flows` | flows |
| `GET` | `/api/v1/analyses/{key}/features` | flow features |
| `GET` | `/api/v1/analyses/{key}/export/{flows\|ike\|esp\|features}` | CSV/JSON export |
| `GET` | `/api/v1/system/tools` | reader + installed tools |

## 12. Known limitations (Phase 2)

- No live capture, no injection, no decryption.
- Works on captured PCAP/PCAPNG files only.
- IKE proposal *status* is inferred from direction, not decrypted.
- `encryption_algorithm` relies on IKE SA proposals present in the same capture.
- TShark is **not installed** on the reference host (reported honestly); the
  scapy/builtin readers are used instead.
- Docker is not installed, so the docker-compose stack was not run; PostgreSQL
  verification was performed against the local Homebrew instance on `:5433`.
- AI/ML scoring, recommendations and StrongSwan integration are Phase 3.