"""Regenerate the deterministic demo PCAP fixtures.

The generated captures are **synthetic test fixtures**: every byte is built in
Python by ``backend/tests/synthetic_pcap.py``. They are not recordings of real
network or VPN traffic and must never be presented as such.

Usage::

    python scripts/make_fixtures.py            # writes into fixtures/

Outputs (all deterministic — re-running produces byte-identical files):

- ``ipsec-demo.pcap``       IKEv2 SA_INIT + AH + ESP + plaintext DNS/UDP mix
- ``ipsec-ikev1.pcap``      IKEv1 aggressive-mode proposal
- ``plaintext-only.pcap``   non-IPsec traffic only (negative control)
"""

from __future__ import annotations

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))

from tests.synthetic_pcap import (  # noqa: E402
    build_ikev1_pcap,
    build_ipsec_pcap,
    build_plaintext_pcap,
)

FIXTURES = {
    "ipsec-demo.pcap": build_ipsec_pcap,
    "ipsec-ikev1.pcap": build_ikev1_pcap,
    "plaintext-only.pcap": build_plaintext_pcap,
}


def main() -> int:
    out_dir = os.path.join(ROOT, "fixtures")
    os.makedirs(out_dir, exist_ok=True)
    for name, builder in FIXTURES.items():
        path = os.path.join(out_dir, name)
        packet_count = builder().write(path)
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        print(f"{name}: {packet_count} packets, {os.path.getsize(path)} bytes")
        print(f"  sha256={digest}")
    print("\nNOTE: synthetic TEST FIXTURES — not real network traffic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
