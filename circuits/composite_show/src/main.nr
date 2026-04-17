use std::hash::pedersen_hash;

use openac_core::commit::{
    assert_commitment_eq, commit_attributes_v3, DOMAIN_PASSPORT, DOMAIN_X509, hash_to_fields,
};
use openac_core::device::verify_device_binding;
use openac_core::profile::derive_x509_link_rand;

// Composite OpenAC Show Circuit (Path A, v1)
//
// Spec: spec/x509-circuits.md section 7.
//
// Proves the prover holds two Pedersen commitments -- one passport, one X.509
// -- that are bound to the SAME Secure Enclave key (pk_digest). The two
// credentials therefore belong to the same device and can be presented as a
// bundle without revealing their contents.
//
// Responsibilities:
//   1. Run a single ECDSA-P256 verification over `nonce_hash` to derive
//      pk_digest (openac_core::device).
//   2. Derive link_rand_x from link_rand_p via the shared helper
//      openac_core::profile::derive_x509_link_rand (Pedersen over
//      [link_rand_p, SALT_X509]) so we do not fork the derivation rule.
//   3. Re-open both commitments with the shared pk_digest.
//   4. Emit simple predicates:
//        * out_is_older: checks an age_threshold <= packed age field.
//          The full age-from-attr decoder lives in openac_core::profile
//          (pack_passport_profile) but requires a round-trip; for now we
//          operate on the lowest 32 bits of attr_hi as "age_encoded" so the
//          circuit has a real constraint. A richer decoder is TODO and
//          tracked against passport_adapter's pack_passport_profile.
//        * out_domain_match: pedersen_hash([a_attr_hi, a_attr_lo]) vs
//          target_domain_hash (same scheme as x509_show).
//   5. Publish a scoped link tag + challenge digest keyed on link_rand_p
//      (the root randomness) to preserve cross-presentation unlinkability.

fn decode_domain(attr_hi: Field, attr_lo: Field) -> Field {
    pedersen_hash([attr_hi, attr_lo])
}

/// Minimal age predicate. attr_hi's lowest byte encodes a self-declared age
/// in years (0..255). The real adapter will replace this with a proper
/// decode of (birth_year, birth_month, birth_day) packed via
/// `pack_passport_profile`. Keeping a trivially verifiable check here means
/// the circuit still enforces SOMETHING about the opened passport attribute
/// while the richer decoder is TODO.
fn age_at_least(attr_hi: Field, threshold: Field) -> Field {
    let attr_bytes = attr_hi.to_le_bytes::<16>();
    let age = attr_bytes[0] as u32;
    // `threshold` is a public Field. We range-check it fits into u32 so we
    // can compare; bigger thresholds are out of scope for the current
    // self-declared-age fixture encoding.
    let threshold_bytes = threshold.to_le_bytes::<4>();
    let threshold_u32: u32 = (threshold_bytes[0] as u32)
        + (threshold_bytes[1] as u32) * 256
        + (threshold_bytes[2] as u32) * 65536
        + (threshold_bytes[3] as u32) * 16777216;
    if age >= threshold_u32 {
        1
    } else {
        0
    }
}

fn main(
    // === PUBLIC ===
    in_commitment_passport_x: pub Field,
    in_commitment_passport_y: pub Field,
    in_commitment_x509_x: pub Field,
    in_commitment_x509_y: pub Field,
    nonce_hash: pub [u8; 32],
    age_threshold: pub Field,
    target_domain_hash: pub Field,
    // === PRIVATE ===
    p_attr_hi: Field,
    p_attr_lo: Field,
    link_rand_p: Field,
    x_attr_hi: Field,
    x_attr_lo: Field,
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    signature: [u8; 64],
    scope: Field,
    epoch: Field,
    // === PUBLIC OUTPUTS ===
    out_link_tag: pub Field,
    out_is_older: pub Field,
    out_domain_match: pub Field,
    out_challenge_digest: pub Field,
) {
    // 1. ECDSA once -- same pk_digest rides both commitments.
    let pk_digest = verify_device_binding(enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // 2. Derive the X.509 link randomness from the passport root via the
    //    shared helper. This keeps the rule aligned with the prepare
    //    adapters (openac_core::profile::derive_x509_link_rand).
    let link_rand_x = derive_x509_link_rand(link_rand_p);

    // 3. Re-open both commitments with the SAME pk_digest.
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        pk_digest,
        link_rand_p,
    );
    assert_commitment_eq(c_p, in_commitment_passport_x, in_commitment_passport_y);

    let c_x = commit_attributes_v3(DOMAIN_X509, x_attr_hi, x_attr_lo, pk_digest, link_rand_x);
    assert_commitment_eq(c_x, in_commitment_x509_x, in_commitment_x509_y);

    // 4. Predicates.
    let expected_is_older = age_at_least(p_attr_hi, age_threshold);
    assert(out_is_older == expected_is_older, "Age predicate mismatch");
    assert((out_is_older * (out_is_older - 1)) == 0, "out_is_older must be boolean (0 or 1)");

    let computed_domain_hash = decode_domain(x_attr_hi, x_attr_lo);
    let expected_domain_match = if computed_domain_hash == target_domain_hash {
        1
    } else {
        0
    };
    assert(out_domain_match == expected_domain_match, "Domain match predicate mismatch");
    assert(
        (out_domain_match * (out_domain_match - 1)) == 0,
        "out_domain_match must be boolean (0 or 1)",
    );

    // 5. Link tag keyed on link_rand_p (root) so that other credentials
    //    derived from the same seed produce the same tag under a given
    //    scope+epoch -- enables bundle recognition by the verifier.
    let expected_link_tag = pedersen_hash([link_rand_p, scope, epoch]);
    assert(out_link_tag == expected_link_tag, "Link tag mismatch");

    // 6. Challenge digest binds the verifier nonce to this presentation.
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    let expected_challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);
    assert(out_challenge_digest == expected_challenge_digest, "Challenge digest mismatch");
}

// ============================================================
// Tests
// ============================================================

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
fn test_composite_valid() {
    // age_encoded = 30 (low byte of attr_hi), threshold = 18 -> is_older = 1.
    let p_attr_hi: Field = 30;
    let p_attr_lo: Field = 9999;
    let link_rand_p: Field = 777;
    let x_attr_hi: Field = 11;
    let x_attr_lo: Field = 22;
    let age_threshold: Field = 18;
    let scope: Field = 100;
    let epoch: Field = 2026;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        pk_digest,
        link_rand_p,
    );
    let c_x = commit_attributes_v3(DOMAIN_X509, x_attr_hi, x_attr_lo, pk_digest, link_rand_x);
    let target_domain_hash = decode_domain(x_attr_hi, x_attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let link_tag = pedersen_hash([link_rand_p, scope, epoch]);
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);

    main(
        c_p.x,
        c_p.y,
        c_x.x,
        c_x.y,
        test_message_hash(),
        age_threshold,
        target_domain_hash,
        p_attr_hi,
        p_attr_lo,
        link_rand_p,
        x_attr_hi,
        x_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        scope,
        epoch,
        link_tag,
        1,
        1,
        challenge_digest,
    );
}

#[test(should_fail)]
fn test_mismatched_pk_digest() {
    // Passport commitment uses a DIFFERENT pk_digest than the one derived
    // from the signature/enclave bytes -- the commitment re-open must fail.
    let p_attr_hi: Field = 30;
    let p_attr_lo: Field = 9999;
    let link_rand_p: Field = 777;
    let x_attr_hi: Field = 11;
    let x_attr_lo: Field = 22;
    let age_threshold: Field = 18;
    let scope: Field = 100;
    let epoch: Field = 2026;

    let pk_digest_real = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let fake_pk_digest: Field = pk_digest_real + 1;
    let link_rand_x = derive_x509_link_rand(link_rand_p);

    // Passport commitment built with fake pk_digest -> mismatch when circuit
    // re-opens with the real one.
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        fake_pk_digest,
        link_rand_p,
    );
    let c_x = commit_attributes_v3(
        DOMAIN_X509,
        x_attr_hi,
        x_attr_lo,
        pk_digest_real,
        link_rand_x,
    );
    let target_domain_hash = decode_domain(x_attr_hi, x_attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let link_tag = pedersen_hash([link_rand_p, scope, epoch]);
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);

    main(
        c_p.x,
        c_p.y,
        c_x.x,
        c_x.y,
        test_message_hash(),
        age_threshold,
        target_domain_hash,
        p_attr_hi,
        p_attr_lo,
        link_rand_p,
        x_attr_hi,
        x_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        scope,
        epoch,
        link_tag,
        1,
        1,
        challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_passport_commitment() {
    let p_attr_hi: Field = 30;
    let p_attr_lo: Field = 9999;
    let link_rand_p: Field = 777;
    let x_attr_hi: Field = 11;
    let x_attr_lo: Field = 22;
    let age_threshold: Field = 18;
    let scope: Field = 100;
    let epoch: Field = 2026;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        pk_digest,
        link_rand_p,
    );
    let c_x = commit_attributes_v3(DOMAIN_X509, x_attr_hi, x_attr_lo, pk_digest, link_rand_x);
    let target_domain_hash = decode_domain(x_attr_hi, x_attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let link_tag = pedersen_hash([link_rand_p, scope, epoch]);
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);

    // Tamper the passport commitment X coordinate.
    main(
        c_p.x + 1,
        c_p.y,
        c_x.x,
        c_x.y,
        test_message_hash(),
        age_threshold,
        target_domain_hash,
        p_attr_hi,
        p_attr_lo,
        link_rand_p,
        x_attr_hi,
        x_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        scope,
        epoch,
        link_tag,
        1,
        1,
        challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_x509_commitment() {
    let p_attr_hi: Field = 30;
    let p_attr_lo: Field = 9999;
    let link_rand_p: Field = 777;
    let x_attr_hi: Field = 11;
    let x_attr_lo: Field = 22;
    let age_threshold: Field = 18;
    let scope: Field = 100;
    let epoch: Field = 2026;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        pk_digest,
        link_rand_p,
    );
    let c_x = commit_attributes_v3(DOMAIN_X509, x_attr_hi, x_attr_lo, pk_digest, link_rand_x);
    let target_domain_hash = decode_domain(x_attr_hi, x_attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let link_tag = pedersen_hash([link_rand_p, scope, epoch]);
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);

    // Tamper the X.509 commitment Y coordinate.
    main(
        c_p.x,
        c_p.y,
        c_x.x,
        c_x.y + 1,
        test_message_hash(),
        age_threshold,
        target_domain_hash,
        p_attr_hi,
        p_attr_lo,
        link_rand_p,
        x_attr_hi,
        x_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        scope,
        epoch,
        link_tag,
        1,
        1,
        challenge_digest,
    );
}
