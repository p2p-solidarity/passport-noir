use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;

use crate::commit::hash_to_fields;

// OpenAC Path A device-binding helpers.
//
// This module folds ECDSA-P256 enclave signature verification and the
// public-key digest derivation into reusable functions. The resulting
// pk_digest is designed to be consumed by commit::commit_attributes_v3 so
// that a single Pedersen commitment simultaneously binds the credential
// attributes and the enclave key -- no separate device-binding proof
// is required in Path A.
//
// Design notes:
//   * Noir bn254 native Field is ~254 bits, so a full P-256 coordinate
//     (256 bits) does not fit in one Field. Each coord is split into two
//     128-bit (big-endian) Field elements via the shared `hash_to_fields`
//     helper from `commit`.
//   * The digest uses `pedersen_hash` (the same primitive already used in
//     profile.nr) with a domain separator constant so pk digests cannot
//     collide with other pedersen-hashed values in this library. The task
//     description suggested poseidon::bn254::hash_4, but that path is not
//     public in nargo 1.0.0-beta.19's stdlib (only poseidon2_permutation
//     is exposed). pedersen_hash over 5 Field inputs (domain + 4 coord
//     halves) gives an equivalent 254-bit domain-separated digest and
//     keeps the whole library on a single hash primitive.

/// Domain separator for enclave public-key digests. ASCII "pkdg".
global DOMAIN_PK_DIGEST: Field = 0x706b6467;

/// Verifies an enclave ECDSA-P256 signature over `nonce_hash` and returns
/// the pk_digest for commitment binding.
///
/// All pk_x / pk_y bytes are private witnesses. `nonce_hash` is expected
/// to be a public input supplied by the verifier (per OpenAC show phase).
/// Panics with a descriptive message on verification failure.
pub fn verify_device_binding(
    enclave_pk_x_bytes: [u8; 32],
    enclave_pk_y_bytes: [u8; 32],
    signature: [u8; 64],
    nonce_hash: [u8; 32],
) -> Field {
    // 1. ECDSA P-256 verify (Noir native black-box).
    let valid = verify_signature(
        enclave_pk_x_bytes,
        enclave_pk_y_bytes,
        signature,
        nonce_hash,
    );
    assert(valid, "Device binding: ECDSA P-256 signature verification failed");

    // 2. Derive pk_digest from the verified public key coordinates.
    pk_digest_from_bytes(enclave_pk_x_bytes, enclave_pk_y_bytes)
}

/// Computes pk_digest from an enclave P-256 public key without performing
/// ECDSA verification. Used by the Prepare circuit, where no fresh nonce
/// signature is available yet but the commitment still needs to bind the
/// key so that the Show circuit can later assert consistency.
pub fn pk_digest_from_bytes(enclave_pk_x_bytes: [u8; 32], enclave_pk_y_bytes: [u8; 32]) -> Field {
    let (pk_x_hi, pk_x_lo) = hash_to_fields(enclave_pk_x_bytes);
    let (pk_y_hi, pk_y_lo) = hash_to_fields(enclave_pk_y_bytes);
    pedersen_hash([DOMAIN_PK_DIGEST, pk_x_hi, pk_x_lo, pk_y_hi, pk_y_lo])
}

// ============================================================
// Tests
// ============================================================
// Valid ECDSA-P256 fixture copied verbatim from
// circuits/device_binding/src/main.nr to keep the Path A helper on the
// same canonical test vector as the standalone device_binding circuit.
// Message: SHA256("openac_device_binding_test_v2").

fn test_pub_key_x() -> [u8; 32] {
    [
        0x43, 0xa3, 0x93, 0x7c, 0xff, 0x2b, 0xcb, 0x51, 0xd0, 0x93, 0xf0, 0x01, 0x7c, 0x32, 0x99,
        0xef, 0x5f, 0xec, 0x7c, 0x97, 0x16, 0xd5, 0xb9, 0xc6, 0x76, 0xfd, 0xaf, 0x78, 0xc2, 0x0b,
        0x0f, 0x78,
    ]
}

fn test_pub_key_y() -> [u8; 32] {
    [
        0x4f, 0x95, 0x5f, 0x33, 0xc0, 0x93, 0x45, 0x2f, 0x18, 0xcd, 0xb7, 0x68, 0x54, 0xef, 0x29,
        0x11, 0xe3, 0x7c, 0x51, 0xc9, 0x5c, 0x78, 0x1a, 0x00, 0xb6, 0xa8, 0xfb, 0x51, 0x5b, 0x4e,
        0xeb, 0x4a,
    ]
}

fn test_signature() -> [u8; 64] {
    [
        0x6e, 0xd8, 0x75, 0x24, 0xa9, 0xc8, 0x44, 0xad, 0x2c, 0x67, 0x2c, 0x33, 0xaa, 0x15, 0x73,
        0xdd, 0xcc, 0xba, 0x5a, 0x2c, 0x74, 0xf6, 0xa6, 0xbd, 0xb3, 0x40, 0xcf, 0x18, 0xac, 0xd8,
        0x43, 0x89, 0x1c, 0xd8, 0xf8, 0xa8, 0x63, 0x76, 0x98, 0x3c, 0x44, 0xa2, 0x9a, 0x61, 0xe9,
        0x0c, 0x85, 0xc0, 0x37, 0x34, 0xd6, 0xb3, 0xba, 0x68, 0xb3, 0xaa, 0xbc, 0x9f, 0x64, 0x11,
        0xe1, 0x3b, 0x45, 0x4c,
    ]
}

fn test_message_hash() -> [u8; 32] {
    [
        0xd6, 0xe9, 0xef, 0x3f, 0xc3, 0x44, 0x1a, 0xb5, 0x33, 0xb3, 0x84, 0x31, 0xda, 0x4c, 0xa9,
        0x67, 0x49, 0xaf, 0x9a, 0x3e, 0x2f, 0x8e, 0x99, 0x35, 0x38, 0x91, 0xbd, 0xf4, 0x05, 0x94,
        0x5a, 0xde,
    ]
}

#[test]
fn test_pk_digest_deterministic() {
    let pk_x: [u8; 32] = [0xAA; 32];
    let pk_y: [u8; 32] = [0xBB; 32];
    let d1 = pk_digest_from_bytes(pk_x, pk_y);
    let d2 = pk_digest_from_bytes(pk_x, pk_y);
    assert(d1 == d2, "pk_digest must be deterministic for identical key bytes");
}

#[test]
fn test_pk_digest_sensitive_to_x() {
    let pk_y: [u8; 32] = [0xBB; 32];
    let mut pk_x_a: [u8; 32] = [0xAA; 32];
    let mut pk_x_b: [u8; 32] = [0xAA; 32];
    pk_x_b[0] = 0x01;
    let d_a = pk_digest_from_bytes(pk_x_a, pk_y);
    let d_b = pk_digest_from_bytes(pk_x_b, pk_y);
    assert(d_a != d_b, "pk_digest must change when pk_x changes");
}

#[test]
fn test_pk_digest_sensitive_to_y() {
    let pk_x: [u8; 32] = [0xAA; 32];
    let mut pk_y_a: [u8; 32] = [0xBB; 32];
    let mut pk_y_b: [u8; 32] = [0xBB; 32];
    pk_y_b[31] = 0x01;
    let d_a = pk_digest_from_bytes(pk_x, pk_y_a);
    let d_b = pk_digest_from_bytes(pk_x, pk_y_b);
    assert(d_a != d_b, "pk_digest must change when pk_y changes");
}

#[test]
fn test_verify_device_binding_valid() {
    let digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    // Verify helper returns the same digest that pk_digest_from_bytes would.
    let direct = pk_digest_from_bytes(test_pub_key_x(), test_pub_key_y());
    assert(
        digest == direct,
        "verify_device_binding must return pk_digest_from_bytes for the same key",
    );
}

#[test(should_fail)]
fn test_verify_device_binding_invalid_signature() {
    let mut bad_sig = test_signature();
    bad_sig[0] ^= 0xFF;
    let _ = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        bad_sig,
        test_message_hash(),
    );
}

#[test(should_fail)]
fn test_verify_device_binding_invalid_pk() {
    let mut bad_pk_x = test_pub_key_x();
    bad_pk_x[0] ^= 0xFF;
    let _ = verify_device_binding(
        bad_pk_x,
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
}
