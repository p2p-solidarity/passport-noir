use std::ecdsa_secp256r1::verify_signature;

// OpenAC Device Binding Circuit
//
// Paper C2: "Assert ECDSA.verify(sigma_nonce, m_1[1]) = 1"
// i.e., the live nonce signature corresponds to the device public key.
//
// This circuit is SEPARATE from the show circuit to keep the show circuit lean.
// Device binding is optional -- without it, proofs are transferable (the verifier
// must trust that the prover is the credential holder).
//
// With device binding:
//   - Non-transferability: proof is bound to the device's Secure Enclave key
//   - Freshness: nonce from verifier prevents replay
//
// Flow:
//   1. Verifier sends challenge (nonce_V)
//   2. Device signs H(nonce_V) with Secure Enclave key SK_D
//   3. This circuit verifies the signature under PK_D
//   4. Verifier checks this proof alongside prepare + show proofs
//
// Note: ECDSA P-256 verification on bn254 is wrong-field arithmetic (~100k+ constraints).
// On T256 curve it would be native, but we stay on bn254 for Noir/mopro compatibility.

fn main(
    // Private: ECDSA signature (r || s, 32 bytes each)
    signature: [u8; 64],
    // Public: device public key (uncompressed, x and y coordinates)
    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    // Public: message hash = SHA256(challenge_nonce)
    message_hash: pub [u8; 32],
) {
    let valid = verify_signature(pub_key_x, pub_key_y, signature, message_hash);
    assert(valid, "Device binding ECDSA P-256 verification failed");
}

// ============================================================
// Tests
// ============================================================
// Test vectors generated via Python cryptography library (ECDSA P-256 / secp256r1).
// Message: SHA256("openac_device_binding_test_v2")

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
fn test_valid_device_signature() {
    main(
        test_signature(),
        test_pub_key_x(),
        test_pub_key_y(),
        test_message_hash(),
    );
}

#[test(should_fail)]
fn test_zero_signature_fails() {
    let sig: [u8; 64] = [0; 64];
    let pk_x: [u8; 32] = [0; 32];
    let pk_y: [u8; 32] = [0; 32];
    let msg: [u8; 32] = [0; 32];

    main(sig, pk_x, pk_y, msg);
}

#[test(should_fail)]
fn test_wrong_message_hash_fails() {
    let mut wrong_hash = test_message_hash();
    wrong_hash[0] ^= 0xFF;
    main(
        test_signature(),
        test_pub_key_x(),
        test_pub_key_y(),
        wrong_hash,
    );
}

#[test(should_fail)]
fn test_wrong_public_key_fails() {
    let mut wrong_pk_x = test_pub_key_x();
    wrong_pk_x[0] ^= 0xFF;
    main(
        test_signature(),
        wrong_pk_x,
        test_pub_key_y(),
        test_message_hash(),
    );
}
