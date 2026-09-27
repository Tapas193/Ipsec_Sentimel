"""IKE (ISAKMP) message dissector.

Parses the IKE header and generic payload chain for both IKEv1 (RFC 2409)
and IKEv2 (RFC 7296) at the bytes level. Crypto transforms are labelled from
the IANA registries; anything that cannot be positively identified is
reported as ``UNKNOWN``. Encrypted payloads are never decrypted.
"""

from __future__ import annotations

from app.analyzers.packet_analyzer.packet_models import (
    IkeLayer,
    IkeMessageRecord,
    IkeProposalData,
    ParsedPacket,
)

IKE_HEADER_LEN = 28

# --- Exchange types ---------------------------------------------------------

_IKEV2_EXCHANGES: dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
}

_IKEV1_EXCHANGES: dict[int, str] = {
    0: "NONE",
    1: "BASE",
    2: "IDENTITY_PROTECTION",
    3: "AUTHENTICATION_ONLY",
    4: "AGGRESSIVE",
    5: "INFORMATIONAL",
    6: "NEW_GROUP_MODE",
    7: "QUICK_MODE",
}

# --- Payload types ----------------------------------------------------------

_IKEV2_PAYLOADS: dict[int, str] = {
    0: "NONE",
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    42: "DELETE",
    43: "VENDOR_ID",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
    51: "GSA",
}

_IKEV1_PAYLOADS: dict[int, str] = {
    0: "NONE",
    1: "SA",
    2: "PROPOSAL",
    3: "TRANSFORM",
    4: "KE",
    5: "ID",
    6: "CERT",
    7: "CERTREQ",
    8: "HASH",
    9: "SIG",
    10: "NONCE",
    11: "NOTIFY",
    12: "DELETE",
    13: "VENDOR_ID",
    19: "NAT_D",
    20: "NAT_OA",
}

# --- Protol IDs inside SA proposals -----------------------------------------

_IKEV2_PROTOCOLS: dict[int, str] = {1: "IKE", 2: "AH", 3: "ESP"}
_IKEV1_PROTOCOLS: dict[int, str] = {1: "ISAKMP", 2: "AH", 3: "ESP"}

# --- Crypto transforms (IANA registries) ------------------------------------

_ENCR_V2: dict[int, str] = {
    1: "DES",
    2: "3DES",
    3: "RC5",
    4: "IDEA",
    5: "CAST",
    6: "BLOWFISH",
    7: "3IDEA",
    8: "DES_IV64",
    9: "DES_IV32",
    11: "NULL",
    12: "AES_CBC",
    13: "AES_CTR",
    14: "AES_CCM_8",
    15: "AES_CCM_12",
    16: "AES_CCM_16",
    18: "AES_GCM_16",
    19: "AES_GCM_12",
    20: "AES_GCM_8",
    22: "AES_CBC_192",
    23: "AES_CBC_256",
    24: "AES_CTR_192",
    25: "AES_CTR_256",
}

_INTEG_V2: dict[int, str] = {
    0: "NONE",
    1: "HMAC_MD5_96",
    2: "HMAC_SHA1_96",
    3: "HMAC_TIGER",
    4: "AES_XCBC_96",
    5: "HMAC_SHA2_256_128",
    6: "HMAC_SHA2_384_192",
    7: "HMAC_SHA2_512_256",
    8: "HMAC_SHA2_256_TRUNC128",
    9: "AES_CMAC_96",
    10: "AES_128_GMAC",
    11: "AES_192_GMAC",
    12: "AES_256_GMAC",
}

_PRF_V2: dict[int, str] = {
    1: "HMAC_MD5",
    2: "HMAC_SHA1",
    3: "HMAC_TIGER",
    4: "AES128_XCBC",
    5: "HMAC_SHA2_256",
    6: "HMAC_SHA2_384",
    7: "HMAC_SHA2_512",
    8: "AES128_CMAC",
}

_DH_GROUPS: dict[int, str] = {
    1: "MODP_768",
    2: "MODP_1024",
    3: "MODP_1536",
    5: "MODP_2048",
    7: "MODP_163",
    8: "MODP_??",
    9: "MODP_??",
    14: "MODP_2048",
    15: "MODP_3072",
    16: "MODP_4096",
    17: "MODP_6144",
    18: "MODP_8192",
    19: "ECP_256",
    20: "ECP_384",
    21: "ECP_521",
    22: "MODP_1024_S160",
    23: "MODP_2048_S224",
    24: "MODP_2048_S256",
    25: "ECP_192",
    26: "ECP_224",
    27: "BRAINPOOL_P256",
    28: "BRAINPOOL_P384",
    29: "BRAINPOOL_P512",
    30: "CURVE25519",
    31: "CURVE448",
}

_ESN_V2: dict[int, str] = {0: "NO_ESN", 1: "ESN"}

# IKEv1 transform ids (RFC 2407).
_IKEV1_TRANSFORMS: dict[int, str] = {
    1: "DES_CBC",
    2: "IDEA_CBC",
    3: "BLOWFISH_CBC",
    4: "RC5_R16",
    5: "3DES_CBC",
    6: "CAST_CBC",
    7: "AES_CBC",
    8: "AES_CTR",
}

_IKEV1_ATTR_TYPES: dict[int, str] = {
    1: "life_type",
    2: "life_duration",
    3: "group_desc",
    4: "key_length",
    5: "auth_method",
    6: "hash_alg",
    7: "encapsulation_mode",
    11: "key_length_isakmp",
    12: "dh_field_size",
}

_IKEV1_AUTH: dict[int, str] = {
    1: "PSK",
    2: "DSS",
    3: "RSA_SIG",
    4: "RSA_ENC",
    5: "RSA_ENC_REV",
    6: "EL_GAMAL",
    7: "EL_GAMAL_REV",
    8: "ECDSA_SHA",
    9: "X509_SIG",
}

_IKEV1_HASH: dict[int, str] = {1: "MD5", 2: "SHA1"}


def _payload_name(version: str, ptype: int) -> str:
    table = _IKEV2_PAYLOADS if version == "IKEv2" else _IKEV1_PAYLOADS
    return table.get(ptype, f"PAYLOAD_{ptype}")


def parse_ike_header(raw: bytes) -> IkeLayer | None:
    """Parse the 28-byte IKE header and the generic payload chain."""
    if len(raw) < IKE_HEADER_LEN:
        return None

    init_spi = raw[0:8].hex()
    resp_spi = raw[8:16].hex()
    next_payload = raw[16]
    ver = raw[17]
    major, _minor = ver >> 4, ver & 0x0F
    if major == 2:
        version = "IKEv2"
    elif major == 1:
        version = "IKEv1"
    else:
        version = "unknown"
    exchange_type = raw[18]
    flags = raw[19]
    message_id = raw[20:24].hex()
    length = int.from_bytes(raw[24:28], "big")

    exchange_table = _IKEV2_EXCHANGES if version == "IKEv2" else _IKEV1_EXCHANGES
    exchange_name = exchange_table.get(exchange_type, f"EXCHANGE_{exchange_type}")

    payload_types = _scan_payloads(raw[IKE_HEADER_LEN:], next_payload, version)
    sa_payload = _extract_sa_body(raw[IKE_HEADER_LEN:], next_payload, version)

    return IkeLayer(
        version=version,
        initiator_spi=init_spi,
        responder_spi=resp_spi,
        next_payload=next_payload,
        exchange_type=exchange_type,
        exchange_name=exchange_name,
        flags=flags,
        message_id=message_id,
        length=length,
        payload_types=payload_types,
        raw=raw,
        sa_payload=sa_payload,
    )


def _scan_payloads(body: bytes, next_payload: int, version: str) -> list[str]:
    """Walk the generic payload chain and return a list of payload type names."""
    names: list[str] = []
    ptype = next_payload
    offset = 0
    guard = 0
    while ptype != 0 and offset + 4 <= len(body) and guard < 32:
        names.append(_payload_name(version, ptype))
        next_payload = body[offset]
        payload_len = int.from_bytes(body[offset + 2 : offset + 4], "big")
        if payload_len < 4:
            break
        if ptype == 46:  # SK (encrypted payload) — content cannot be parsed
            break
        offset += payload_len
        ptype = next_payload
        guard += 1
    return names


def parse_sa_proposals(
    raw: bytes,
    version: str,
    spi_size: int = 0,
    protocol_id: int | None = None,
) -> list[IkeProposalData]:
    """Parse an SA payload body into crypto proposals.

    ``spi_size`` and ``protocol_id`` let the caller seed the proposal with
    context discovered while walking the IKEv2 proposal chain.
    """
    proposals: list[IkeProposalData] = []
    offset = 0
    guard = 0
    while 0 < offset + 4 <= len(raw) and guard < 16:
        next_byte = raw[offset]
        header_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if header_len < 4 or offset + header_len > len(raw):
            break
        body = raw[offset + 4 : offset + header_len]
        if version == "IKEv2":
            proposal = _parse_v2_proposal(body, header_len)
        else:
            proposal = _parse_v1_proposal(body, header_len)
        if proposal is not None:
            if protocol_id is not None:
                proposal.protocol_id = protocol_id
                proposal.protocol_name = _IKEV2_PROTOCOLS.get(protocol_id, "UNKNOWN")
            if spi_size:
                proposal.status = _negotiation_status_from_spi(spi_size)
            proposals.append(proposal)
        offset += header_len
        if next_byte == 0:
            break
        guard += 1
    return proposals


def _negotiation_status_from_spi(spi_size: int) -> str:
    # A responder proposal carrying a non-zero SPI length is the accepted
    # proposal in IKEv2. This is inferred, not observed directly.
    return "SELECTED" if spi_size else "OFFERED"


def _parse_v2_proposal(body: bytes, header_len: int) -> IkeProposalData | None:
    if len(body) < 4:
        return None
    proposal_num = body[0]
    proto_id = body[1]
    spi_size = body[2]
    num_transforms = body[3]
    if spi_size > 0:
        body = body[4 + spi_size :]
    else:
        body = body[4:]
    if proto_id == 3:
        protocol_name = "ESP"
    elif proto_id == 2:
        protocol_name = "AH"
    elif proto_id == 1:
        protocol_name = "IKE"
    else:
        protocol_name = "UNKNOWN"

    enc, enc_id, key_len = "UNKNOWN", None, None
    integ, integ_id = "UNKNOWN", None
    prf, prf_id = "UNKNOWN", None
    dh_group: int | None = None
    esn: int | None = None

    offset = 0
    parsed = 0
    transform_count = num_transforms if num_transforms > 0 else 16
    while 0 < offset + 4 <= len(body) and parsed < transform_count and parsed < 16:
        t_len = int.from_bytes(body[offset + 2 : offset + 4], "big")
        if t_len < 4 or offset + t_len > len(body):
            break
        t_type = body[offset + 4]
        t_id = int.from_bytes(body[offset + 6 : offset + 8], "big")
        attrs = body[offset + 8 : offset + t_len]
        if t_type == 1:
            enc_id, enc = t_id, _ENCR_V2.get(t_id, f"ENCR_{t_id}")
            key_len = _extract_key_length(attrs)
        elif t_type == 2:
            prf_id, prf = t_id, _PRF_V2.get(t_id, f"PRF_{t_id}")
        elif t_type == 3:
            integ_id, integ = t_id, _INTEG_V2.get(t_id, f"INTEG_{t_id}")
        elif t_type == 4:
            dh_group = t_id
        elif t_type == 5:
            esn = t_id
        offset += t_len
        parsed += 1

    confidence = "high" if parsed > 0 else "low"
    return IkeProposalData(
        proposal_number=proposal_num,
        protocol_id=proto_id,
        protocol_name=protocol_name,
        encryption=enc,
        encryption_id=enc_id,
        key_length=key_len,
        integrity=integ,
        integrity_id=integ_id,
        prf=prf,
        prf_id=prf_id,
        dh_group=dh_group,
        esn=esn,
        transform_confidence=confidence,
    )


def _extract_key_length(attrs: bytes) -> int | None:
    offset = 0
    while offset + 4 <= len(attrs):
        af = attrs[offset] >> 7
        attr_type = attrs[offset] & 0x7F
        if af == 1:
            value = int.from_bytes(attrs[offset + 2 : offset + 4], "big")
            if attr_type == 14:  # KEY_LENGTH
                return value
            offset += 4
        else:
            attr_len = int.from_bytes(attrs[offset + 2 : offset + 4], "big")
            if attr_type == 14 and attr_len >= 2:
                return int.from_bytes(attrs[offset + 4 : offset + 4 + min(attr_len, 4)], "big")
            offset += 4 + attr_len
    return None


def _parse_v1_proposal(body: bytes, header_len: int) -> IkeProposalData | None:
    # IKEv1 proposal payload body: proposal #, protocol id, SPI size, num transforms.
    if len(body) < 4:
        return None
    proposal_num = body[0]
    proto_id = body[1]
    spi_size = body[2]
    proto_name = _IKEV1_PROTOCOLS.get(proto_id, "UNKNOWN")

    offset = 4
    if spi_size and offset + spi_size <= len(body):
        offset += spi_size

    enc, enc_id, key_len = "UNKNOWN", None, None
    integ, integ_id = "UNKNOWN", None
    prf, prf_id = "UNKNOWN", None
    dh_group: int | None = None
    parsed = 0
    while offset + 4 <= len(body) and parsed < 16:
        t_len = int.from_bytes(body[offset + 2 : offset + 4], "big")
        if t_len < 4 or offset + t_len > len(body):
            break
        t_body = body[offset + 4 : offset + t_len]
        if len(t_body) < 3:
            break
        transform_id = t_body[1]
        attrs = _parse_v1_attributes(t_body[3:])
        if transform_id in (1, 5, 7, 8):  # DES / 3DES / AES / AES-CTR
            enc_id = transform_id
            enc = _IKEV1_TRANSFORMS.get(transform_id, f"ALG_{transform_id}")
            if attrs.get("key_length") is not None:
                key_len = int(attrs["key_length"])
            elif attrs.get("key_length_isakmp") is not None:
                key_len = int(attrs["key_length_isakmp"])
        if attrs.get("hash_alg") is not None:
            integ_id = int(attrs["hash_alg"])
            integ = _IKEV1_HASH.get(integ_id, f"HASH_{integ_id}")
        if attrs.get("group_desc") is not None:
            dh_group = int(attrs["group_desc"])
        if attrs.get("auth_method") is not None:
            prf = _IKEV1_AUTH.get(int(attrs["auth_method"]), "AUTH_UNKNOWN")
            prf_id = int(attrs["auth_method"])
        offset += t_len
        parsed += 1

    return IkeProposalData(
        proposal_number=proposal_num,
        protocol_id=proto_id,
        protocol_name=proto_name,
        encryption=enc,
        encryption_id=enc_id,
        key_length=key_len,
        integrity=integ,
        integrity_id=integ_id,
        prf=prf,
        prf_id=prf_id,
        dh_group=dh_group,
        transform_confidence="high" if parsed > 0 else "low",
    )


def _parse_v1_attributes(raw: bytes) -> dict[str, str]:
    """Parse IKEv1 attribute TLVs (RFC 2407, 2-byte header + value)."""
    attrs: dict[str, str] = {}
    offset = 0
    while offset + 2 <= len(raw):
        header = int.from_bytes(raw[offset : offset + 2], "big")
        af = header >> 15
        attr_type = header & 0x7FFF
        name = _IKEV1_ATTR_TYPES.get(attr_type, f"attr_{attr_type}")
        offset += 2
        if af == 1:
            if offset + 2 <= len(raw):
                attrs[name] = str(int.from_bytes(raw[offset : offset + 2], "big"))
                offset += 2
            else:
                break
        else:
            if offset + 2 > len(raw):
                break
            length = int.from_bytes(raw[offset : offset + 2], "big")
            offset += 2
            if offset + length > len(raw):
                break
            attrs[name] = raw[offset : offset + length].hex()
            offset += length
    return attrs


def _extract_sa_body(body: bytes, next_payload: int, version: str) -> bytes | None:
    """Return the bytes of the first SA payload (for proposal parsing)."""
    sa_type = 33 if version == "IKEv2" else 1
    ptype = next_payload
    offset = 0
    guard = 0
    while ptype != 0 and offset + 4 <= len(body) and guard < 32:
        payload_len = int.from_bytes(body[offset + 2 : offset + 4], "big")
        if payload_len < 4 or offset + payload_len > len(body):
            break
        if ptype == sa_type:
            return body[offset + 4 : offset + payload_len]
        if ptype == 46:  # SK — encrypted, no further parsing
            break
        ptype = body[offset]
        offset += payload_len
        guard += 1
    return None


def parse_ike_message(packet: ParsedPacket, layer: IkeLayer) -> IkeMessageRecord | None:
    """Extract a message record including crypto proposals from an IKE layer."""
    if layer is None:
        return None
    if layer.version == "IKEv2":
        is_initiator = bool(layer.flags & 0x01)
        direction = "initiator" if is_initiator else "responder"
        status = "OFFERED" if is_initiator else "SELECTED"
    else:
        direction = "unknown"
        status = "OFFERED"
    record = IkeMessageRecord(
        packet_id=packet.number,
        timestamp=packet.timestamp,
        source_ip=packet.source,
        destination_ip=packet.destination,
        source_port=packet.source_port or 0,
        destination_port=packet.destination_port or 0,
        version=layer.version,
        exchange_type=layer.exchange_type,
        exchange_name=layer.exchange_name,
        flags=layer.flags,
        message_id=layer.message_id,
        length=layer.length,
        next_payload=layer.next_payload,
        payload_types=layer.payload_types,
        initiator_spi=layer.initiator_spi,
        responder_spi=layer.responder_spi,
        direction=direction,
    )
    if layer.sa_payload:
        proposals = parse_sa_proposals(layer.sa_payload, layer.version)
        for proposal in proposals:
            proposal.status = status
        record.proposals = proposals
    return record
