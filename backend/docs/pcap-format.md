# Supported Capture Formats — IPsec Sentinel (Phase 2)

## 1. What is accepted

Uploads must be one of:

| Format | Extension(s) | Detection |
| --- | --- | --- |
| PCAP (classic libpcap) | `.pcap`, `.cap` | magic bytes `d4 c3 b2 a1` (LE), `a1 b2 c3 d4` (BE), nanosecond variants |
| PCAPNG | `.pcapng` | magic bytes `0a 0d 0d 0a` |

Files whose magic bytes don't match are rejected with `UNSUPPORTED_FORMAT`
during upload — an on-disk extension alone is not trusted.

## 2. Validation rules

Applied in `app/services/capture_store.py`:

1. filename present, not `.` / `..`, no path separators
2. extension in allow-list
3. content non-empty
4. size ≤ `MAX_UPLOAD_SIZE_MB`
5. magic-byte signature recognized

SHA-256 is computed over the exact uploaded bytes and stored; it is the capture's
integrity identity and is shown in the UI.

## 3. How frames are read

The active reader (see §below) yields frames as `(number, timestamp, raw bytes)`:

- **TShark**: `tshark -r <file> -T json -x` (raw-hex layers). Timeout 120 s.
- **Scapy**: `rdpcap` — needs `scapy` installed.
- **Builtin**: dependency-free pcap/pcapng reader implemented in
  `app/analyzers/packet_analyzer/reader.py`. It parses the global header, block
  types (`SHB/IDB/EPB/PB` for pcapng; record series for pcap), handles
  link-type, byte order, nanosecond timestamps, and trimmed/truncated record
  handling. Captured length is clamped to the available bytes.

Every reader feeds the *same* parser, so results are reader-independent.

## 4. Frame to packet mapping

Per frame the parser decodes:

```
Ethernet (EtherType / VLAN)
  └── IPv4 / IPv6
        ├── UDP:500          → IKE
        ├── UDP:4500         → IKE (NAT-T) or ESP (payload starts with ESP header)
        ├── UDP:other        → general flow traffic
        ├── TCP:500/4500     → IKE over TCP (where present)
        ├── IP proto 50      → ESP
        └── IP proto 51      → AH
```

Non-IP traffic and unparsed IP payloads are still counted for protocol
observations and flows (e.g. ARP appears in `protocol-observations`).

## 5. Link types handled by the builtin reader

- Ethernet (10/100/1000/2.5G/5G/10G, DLT 1) — primary target
- Raw IP (DLT 101, modified raw DLT 12) — best effort on some samples
- `USER0` (DLT 147) and `LOOP` (26) are treated as Ethernet for common
  capture-ng/loopback compatibility where bytes start with an Ethernet header.

Anything unrecognized is stored honestly: the frame is preserved for flow/byte
counting but flagged so consumers don't over-interpret.

## 6. Edge cases & honesty rules

- A valid-magic file with corrupt/truncated packets: stored (magic is valid) and
  parsed defensively — bad records skipped, no crash, packet count reflects what
  was actually decoded.
- An empty capture (24-byte header, 0 packets): stored, analyzable, produces an
  analysis with 0 packets and `protocol_detected=no`.
- Unknown transform/encryption ids → `UNKNOWN`, never guessed.
- ESP over UDP 4500: a leading 4-byte zero word marks the non-ESP marker; actual
  ESP payloads start directly with the ESP header (SPI first).
- No decryption is ever attempted.

## 7. Reference capture for testing

`backend/tests/synthetic_pcap.py` builds a deterministic synthetic capture used by
the test suite and by `backend/scripts/pg_e2e.py`:

- 22 packets: 4 IKE (2× initiator/responder with SA proposals), 12 ESP, 3 AH,
  ARP + TCP filler
- fixed content → fixed SHA-256 `411fef80a46a2ba0dfa0116fddfbe78c4308cb67a887d78163e65bc2c4cfd78f`
- produces `protocol_detected=yes`, confidence `high`, 5 observations,
  4 flows, 4 feature sets

Real-world captures (Wireshark/tcpdump/dumpcap) in `.pcap` or `.pcapng` are
valid input as long as magic bytes are recognized.