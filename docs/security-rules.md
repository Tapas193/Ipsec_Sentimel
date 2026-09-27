# Security Rules Catalogue — IPsec Sentinel (v`1.0.0`)

Deterministic rules evaluated by the Phase 3 assessment engine
(`app.security.rules`). Every rule is a pure function of the persisted Phase 2
data of a completed analysis. Rules never re-parse a PCAP, never decrypt, and
never report a value they could not observe.

**Severity semantics** — from the explicit rule/condition table below; never
computed. **Confidence semantics** — `HIGH` = directly observed from the
capture; `MEDIUM` = inferred/aggregated but still evidence-grounded; `LOW` =
the claim is plausible but structurally hard to confirm (e.g. conflicting
SELECTED proposals).

Reference result set for the synthetic regression capture (4× IKE_SA_INIT,
10–12 ESP, 3 AH, plain DNS/UDP alongside):
**exactly three findings** — `IPSEC-CRYPTO-001`, `IPSEC-IKE-001`,
`IPSEC-META-001`. A plaintext-only capture yields **zero** findings.

---

## Cryptography

### `IPSEC-CRYPTO-001` — Encryption could not be verified from the capture
- Severity `LOW` · Type `informational` · Category `VISIBILITY` · Conf. `HIGH`
- Fires when ESP records carry `encryption_algorithm` that is `UNKNOWN`,
  empty, or an unresolved `ENCR_<id>` string, or when IKE proposals reference
  an unrecognized encryption transform. ESP payloads are never decrypted.
- Separate findings are emitted for the ESP side and the IKE-proposal side.
- **Never fires** for a recognized algorithm (e.g. `AES_GCM_16`).

### `IPSEC-CRYPTO-002` — Weak encryption algorithm in use
- Category `CRYPTOGRAPHY` · Type `vulnerability_indicator`
- Static weak set with per-algorithm severity:

| Algorithm(s) | Severity |
| --- | --- |
| `NULL` | `CRITICAL` |
| `DES`, `DES_CBC`, `DES_IV64`, `DES_IV32`, `RC5(+R16)`, `IDEA(+CBC)`, `3IDEA`, `CAST(+CBC)`, `BLOWFISH(+CBC)` | `HIGH` |
| `3DES`, `3DES_CBC` | `MEDIUM` |
| `AES_CBC/CTR/GCM_*` with `key_length < 128` | `HIGH` |

- Confidence `HIGH` if any affected proposal has `transform_confidence ==
  high`, else `MEDIUM`.
- One finding per distinct `(encryption, key_length)` group.
- *Unknown* algorithms are **never** reported here — only explicit table
  matches. A strong AES proposal produces no finding.

## Key exchange

### `IPSEC-DH-001` — Weak Diffie-Hellman group in use
- Category `KEY_EXCHANGE` · Type `vulnerability_indicator` · Confidence `HIGH`
- Weak groups: `1` (MODP_768, HIGH), `2` (MODP_1024, HIGH), `3` (MODP_1536,
  MEDIUM), `22` (MODP_1024_S160, HIGH).
- Absent (`None`) or unrecognized groups are never reported.

### `IPSEC-PFS-001` — Perfect forward secrecy not observed for child SAs
- Category `PFS` · Type `policy_deviation` · Severity `MEDIUM` · Conf. `HIGH`
- Fires *only* when child-SA exchanges (`CREATE_CHILD_SA` / `QUICK_MODE`) are
  directly visible **without** a KE payload or a proposal carrying a DH group.
- **No child exchange in the capture → PFS posture is `UNKNOWN` → no
  finding** ("no evidence → no finding").

## IKE protocol

### `IPSEC-IKE-001` — IKE negotiation may be incomplete
- Category `PROTOCOL` · Type `configuration_risk` · Severity `LOW` ·
  Confidence `MEDIUM` (inferred)
- Setup exchanges (`IKE_SA_INIT`, `BASE`, `IDENTITY_PROTECTION`,
  `AGGRESSIVE`) present, **no** later-stage exchange (`IKE_AUTH`,
  `CREATE_CHILD_SA`, `INFORMATIONAL`, `QUICK_MODE`, …) in the capture, **and**
  ESP/AH traffic present. The capture may be partial — this is stated honestly
  in the finding.

### `IPSEC-SA-001` — Selected security association could not be fully verified
- Category `SECURITY_ASSOCIATION`
- **Unresolved transforms:** a `SELECTED` proposal with integrity/PRF that
  could not be resolved (`UNKNOWN`, `INTEG_*`, `PRF_*`, `HASH_*`, `AUTH_*`,
  `ALG_*`) → severity `MEDIUM`, confidence `MEDIUM`.
- **Conflicting selections:** multiple `SELECTED` proposals for the same
  SA (protocol + SPI pair) → severity `HIGH`, type `vulnerability_indicator`,
  confidence `LOW` (the conflict is structurally hard to confirm).
- Clean, fully-resolved `SELECTED` proposals produce no finding.

## ESP / AH

### `IPSEC-REPLAY-001` — Non-increasing ESP/AH sequence numbers observed
- Category `REPLAY_PROTECTION` · Type `vulnerability_indicator` · Sev.
  `MEDIUM` · Conf. `MEDIUM` (inferred)
- Per `(SPI, direction)`: sequence numbers that do not strictly increase.
  32-bit counter wraps (a drop greater than 2³¹) are treated as a wrap, not an
  anomaly. Anomalies capped at 25 per protocol stream; ESP and AH are separate
  findings. Findings are intentionally conservative (normal reordering is
  consistent with the same observation).

### `IPSEC-COMPOSITE-001` — ESP and AH both applied to the same SA
- Category `SECURITY_ASSOCIATION` · Type `informational` · Severity `INFO` ·
  Confidence `HIGH`
- Same `(SPI, direction)` carries both ESP and AH packets. Informational only
  — dual protection is a valid deployment, not a vulnerability.

## Metadata / visibility

### `IPSEC-META-001` — Non-IPsec traffic observed alongside IPsec
- Category `METADATA` · Type `informational` · Severity `INFO` · Conf. `HIGH`
- Fires only when `analysis.protocol_detected == "yes"` and the capture
  contains non-IPsec protocols (DNS, HTTP, …). Structural protocols (IPv4,
  IPv6, ARP) are ignored. Signals split tunnelling or unrelated segment noise.

### `IPSEC-META-002` — Elevated IKE initiation frequency observed
- Category `METADATA` · Type `informational` · Severity `INFO` · Conf. `MEDIUM`
- ≥ 20 IKE setup requests (`IKE_SA_INIT`, `AGGRESSIVE`, `BASE`,
  `IDENTITY_PROTECTION`) from the same source to the same destination. One
  finding per offending endpoint pair.

---

## Rule registry checks

At import, `app.security.registry` validates the 10-rule set: unique ids
prefixed `IPSEC-`, membership in the fixed category set, non-empty
title/description. `RULES_VERSION` is stamped onto analyses and findings for
reproducibility.

> **Adding a rule:** implement a subclass of `Rule` with static metadata,
> implement `evaluate(ctx) -> list[FindingDraft]`, register it in
> `app.security.rules.__init__`, and write positive + negative unit tests.
> Bump `RULES_VERSION` when existing rules change semantics.