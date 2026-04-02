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
// Note: ECDSA test vectors require valid P-256 signatures.
// We test compilation and the negative case (zero sig should fail).

#[test(should_fail)]
fn test_zero_signature_fails() {
    let sig: [u8; 64] = [0; 64];
    let pk_x: [u8; 32] = [0; 32];
    let pk_y: [u8; 32] = [0; 32];
    let msg: [u8; 32] = [0; 32];

    main(sig, pk_x, pk_y, msg);
}
