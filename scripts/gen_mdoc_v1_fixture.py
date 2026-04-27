#!/usr/bin/env python3
"""Generate the deterministic ECDSA-P256 fixture used by mdoc_adapter v1+v2.

Run:
    python3 scripts/gen_mdoc_v1_fixture.py

Outputs:
  * Noir constants for circuits/mdoc_adapter/src/main.nr v1/v2 test helpers.
  * Prover.toml fixture body.

Layout of the synthetic mDoc message (165 signed bytes, zero-padded to
MAX_MSG_LEN = 512):

    [0..32)    ASCII header
    [32..67)   claim envelope (35 bytes: digest_id + 0x58 + 0x20 + hash)
    [67..80)   validUntilPrefix (13 bytes: 0x6a + "validUntil" + 0xc0 + 0x74)
    [80..90)   date "2030-12-31" (10 bytes)
    [90..98)   deviceKey COSE_Key prefix (8 bytes)
    [98..130)  deviceKey x (32 bytes: canonical Path A pk_x)
    [130..133) deviceKey y prefix (3 bytes: 0x22 0x58 0x20)
    [133..165) deviceKey y (32 bytes: canonical Path A pk_y)

The deviceKey x and y bytes are exactly the canonical Path A test key
shared with passport_adapter / device_binding so the v2 extraction lands
on the same pk_digest those circuits already use.

ECDSA P-256 is non-deterministic; once the script's signature is checked
in, do not regenerate without also updating the embedded constants.
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Deterministic ECDSA-P256 issuer keypair for mdoc v1/v2 tests.
ISSUER_PRIV_INT = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

MAX_MSG_LEN = 512
MAX_PREIMAGE_LEN = 256
ENCODED_DIGEST_LEN = 35

HEADER = b"MDOC_V1_TEST_FIXTURE_HEADER_____"  # 32 bytes
assert len(HEADER) == 32

# Layout offsets (must agree with circuits/mdoc_adapter/src/main.nr).
ENVELOPE_POS = 32
VALID_UNTIL_PREFIX_POS = 67
VALID_UNTIL_DATE_POS = VALID_UNTIL_PREFIX_POS + 13   # 80
DEVICE_KEY_PREFIX_POS = VALID_UNTIL_DATE_POS + 10    # 90
DEVICE_KEY_X_POS = DEVICE_KEY_PREFIX_POS + 8         # 98
DEVICE_KEY_Y_PREFIX_POS = DEVICE_KEY_X_POS + 32      # 130
DEVICE_KEY_Y_POS = DEVICE_KEY_Y_PREFIX_POS + 3       # 133
MESSAGE_LEN = DEVICE_KEY_Y_POS + 32                  # 165

# CBOR markers.
VALID_UNTIL_PREFIX = bytes([0x6a]) + b"validUntil" + bytes([0xc0, 0x74])
assert len(VALID_UNTIL_PREFIX) == 13
DATE_STR = b"2030-12-31"
assert len(DATE_STR) == 10
DEVICE_KEY_PREFIX = bytes([0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20])
assert len(DEVICE_KEY_PREFIX) == 8
DEVICE_KEY_Y_PREFIX = bytes([0x22, 0x58, 0x20])
assert len(DEVICE_KEY_Y_PREFIX) == 3

# Canonical Path A test key (shared with passport_adapter / device_binding).
DEVICE_KEY_X = bytes([
    0x43, 0xa3, 0x93, 0x7c, 0xff, 0x2b, 0xcb, 0x51, 0xd0, 0x93, 0xf0, 0x01,
    0x7c, 0x32, 0x99, 0xef, 0x5f, 0xec, 0x7c, 0x97, 0x16, 0xd5, 0xb9, 0xc6,
    0x76, 0xfd, 0xaf, 0x78, 0xc2, 0x0b, 0x0f, 0x78,
])
DEVICE_KEY_Y = bytes([
    0x4f, 0x95, 0x5f, 0x33, 0xc0, 0x93, 0x45, 0x2f, 0x18, 0xcd, 0xb7, 0x68,
    0x54, 0xef, 0x29, 0x11, 0xe3, 0x7c, 0x51, 0xc9, 0x5c, 0x78, 0x1a, 0x00,
    0xb6, 0xa8, 0xfb, 0x51, 0x5b, 0x4e, 0xeb, 0x4a,
])


def build_message():
    preimage = bytes([0x10 + i for i in range(64)]) + bytes(MAX_PREIMAGE_LEN - 64)
    preimage_hash = hashlib.sha256(preimage).digest()
    envelope = bytes([0, 0x58, 0x20]) + preimage_hash
    assert len(envelope) == ENCODED_DIGEST_LEN

    parts = [
        HEADER,
        envelope,
        VALID_UNTIL_PREFIX,
        DATE_STR,
        DEVICE_KEY_PREFIX,
        DEVICE_KEY_X,
        DEVICE_KEY_Y_PREFIX,
        DEVICE_KEY_Y,
    ]
    tbs = b"".join(parts)
    assert len(tbs) == MESSAGE_LEN, f"tbs length {len(tbs)} != expected {MESSAGE_LEN}"
    message = tbs + bytes(MAX_MSG_LEN - MESSAGE_LEN)
    assert len(message) == MAX_MSG_LEN
    return preimage_hash, envelope, tbs, message


def main():
    priv_key = ec.derive_private_key(ISSUER_PRIV_INT, ec.SECP256R1())
    pub = priv_key.public_key().public_numbers()
    pub_x = pub.x.to_bytes(32, "big")
    pub_y = pub.y.to_bytes(32, "big")

    preimage_hash, envelope, tbs, message = build_message()

    # P-256 group order. Noir's secp256r1 verify rejects high-s
    # signatures (BIP62-style), so we normalise to low-s before exporting.
    P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    # RFC 6979 deterministic ECDSA: same (k, r, s) every run for a given
    # (private key, message, hash). This keeps the embedded fixture
    # bit-for-bit reproducible as long as the message bytes do not
    # change.
    sig_der = priv_key.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(sig_der)
    if s > P256_N // 2:
        s = P256_N - s
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    priv_key.public_key().verify(
        encode_dss_signature(r, s), tbs, ec.ECDSA(hashes.SHA256()),
    )

    def fmt_array(name, data):
        body = ", ".join(f"0x{b:02x}" for b in data)
        return f"fn {name}() -> [u8; {len(data)}] {{\n    [{body}]\n}}"

    print("# === Noir constants for circuits/mdoc_adapter/src/main.nr ===\n")
    print(f"// Deterministic seed: 0x{ISSUER_PRIV_INT:064x}")
    print(f"// MESSAGE_LEN = {MESSAGE_LEN}")
    print(f"// ENVELOPE_POS = {ENVELOPE_POS}")
    print(f"// VALID_UNTIL_PREFIX_POS = {VALID_UNTIL_PREFIX_POS}")
    print(f"// VALID_UNTIL_DATE_POS = {VALID_UNTIL_DATE_POS}")
    print(f"// DEVICE_KEY_PREFIX_POS = {DEVICE_KEY_PREFIX_POS}\n")
    print(fmt_array("v1_issuer_pk_x", pub_x))
    print()
    print(fmt_array("v1_issuer_pk_y", pub_y))
    print()
    print(fmt_array("v1_issuer_signature", signature))
    print()

    print("# === Prover.toml extras (v2 main fixture) ===\n")
    quoted_message = ", ".join(f'"{b}"' for b in message)
    quoted_signature = ", ".join(f'"{b}"' for b in signature)
    quoted_pub_x = ", ".join(f'"{b}"' for b in pub_x)
    quoted_pub_y = ", ".join(f'"{b}"' for b in pub_y)
    print(f"message_len = \"{MESSAGE_LEN}\"")
    print(f"envelope_positions = [\"{ENVELOPE_POS}\", \"0\", \"0\", \"0\"]")
    print(f"valid_until_prefix_pos = \"{VALID_UNTIL_PREFIX_POS}\"")
    print(f"device_key_prefix_pos = \"{DEVICE_KEY_PREFIX_POS}\"")
    print(f"out_valid_until = \"{20301231}\"")
    print(f"message = [{quoted_message}]")
    print(f"issuer_signature = [{quoted_signature}]")
    print(f"issuer_pk_x = [{quoted_pub_x}]")
    print(f"issuer_pk_y = [{quoted_pub_y}]")


if __name__ == "__main__":
    main()
