use std::hash::pedersen_hash;

use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_X509, hash_to_fields};
use openac_core::device::verify_device_binding;
use openac_core::predicate::decode_domain;

// X.509-only OpenAC Show Circuit (Path A, v1)
//
// Spec: spec/x509-circuits.md section 6.
//
// Responsibilities:
//   1. Re-open the X.509 Pedersen commitment using attributes, shared pk_digest
//      and link_rand_x (derived off-chain from link_rand_p by the caller).
//   2. Verify the enclave ECDSA-P256 signature over `nonce_hash` in-circuit and
//      bind the resulting pk_digest into the commitment opening.
//   3. Evaluate a simple domain predicate: the caller provides the (already
//      hashed) target domain Field; we hash the opened (attr_hi, attr_lo) with
//      pedersen_hash and surface a 0/1 match flag. This keeps the circuit
//      agnostic to the domain encoding decided by the adapter -- the caller
//      precomputes `target_domain_hash = pedersen_hash([target_attr_hi,
//      target_attr_lo])` using the same scheme the adapter used when packing
//      the X.509 profile.
//   4. Emit a scoped link tag and a challenge digest suitable for OpenAC show.
//
// Notes:
//   * Poseidon hash_2 is not exposed in nargo 1.0.0-beta.19 stdlib, so we keep
//     every algebraic hash on pedersen_hash (same primitive as openac_core).
//   * nonce_hash is [u8; 32]; we compress it to two Fields via hash_to_fields
//     before feeding it into pedersen_hash (Field cannot fit 256 bits).

fn main(
    // === PUBLIC ===
    in_commitment_x509_x: pub Field,
    in_commitment_x509_y: pub Field,
    nonce_hash: pub [u8; 32],
    target_domain_hash: pub Field,
    link_scope: pub Field,
    epoch: pub Field,
    // === PRIVATE ===
    attr_hi: Field,
    attr_lo: Field,
    link_rand_x: Field,
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    signature: [u8; 64],
    // === PUBLIC OUTPUTS ===
    out_link_tag: pub Field,
    out_domain_match: pub Field,
    out_challenge_digest: pub Field,
) {
    // 1. ECDSA-P256 + pk_digest derivation (openac_core::device).
    let pk_digest = verify_device_binding(enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // 2. Re-open the X.509 commitment with the shared pk_digest bound in.
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    assert_commitment_eq(c, in_commitment_x509_x, in_commitment_x509_y);

    // 3. Domain predicate. We only surface 0/1; the opened attributes stay
    //    private. The adapter is responsible for packing the domain into
    //    (attr_hi, attr_lo) the same way the verifier packs `target_domain_hash`.
    let computed_domain_hash = decode_domain(attr_hi, attr_lo);
    let expected_match = if computed_domain_hash == target_domain_hash {
        1
    } else {
        0
    };
    assert(out_domain_match == expected_match, "Domain match predicate mismatch");
    assert(
        (out_domain_match * (out_domain_match - 1)) == 0,
        "Domain match must be boolean (0 or 1)",
    );

    // 4. Scoped link tag. Uses link_rand_x (this credential's randomness);
    //    verifier observes only `tag` and cannot unpeel to link_rand_x.
    //    Spec sec 6: (link_scope, epoch) are public so the verifier can bind
    //    the tag to a known session context.
    let expected_link_tag = pedersen_hash([link_rand_x, link_scope, epoch]);
    assert(out_link_tag == expected_link_tag, "Link tag mismatch");

    // 5. Challenge digest binds the verifier's nonce to this presentation.
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    let expected_challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);
    assert(out_challenge_digest == expected_challenge_digest, "Challenge digest mismatch");
}

// ============================================================
// Tests
// ============================================================
// ECDSA-P256 fixture reused from circuits/device_binding so that the show
// circuit stays on the same canonical vector as the standalone binding
// benchmark. Message: SHA256("openac_device_binding_test_v2").

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
fn test_valid_show() {
    let attr_hi: Field = 1;
    let attr_lo: Field = 2;
    let link_rand_x: Field = 3;
    let scope: Field = 4;
    let epoch: Field = 5;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let target_domain_hash = decode_domain(attr_hi, attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let link_tag = pedersen_hash([link_rand_x, scope, epoch]);
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);

    main(
        c.x,
        c.y,
        test_message_hash(),
        target_domain_hash,
        scope,
        epoch,
        attr_hi,
        attr_lo,
        link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        link_tag,
        1,
        challenge_digest,
    );
}

#[test]
fn test_domain_match_true() {
    // target_domain_hash matches -> out_domain_match = 1
    let attr_hi: Field = 111;
    let attr_lo: Field = 222;
    let link_rand_x: Field = 333;
    let scope: Field = 0;
    let epoch: Field = 0;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let target = decode_domain(attr_hi, attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let tag = pedersen_hash([link_rand_x, scope, epoch]);
    let digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);

    main(
        c.x,
        c.y,
        test_message_hash(),
        target,
        scope,
        epoch,
        attr_hi,
        attr_lo,
        link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        tag,
        1,
        digest,
    );
}

#[test]
fn test_domain_match_false() {
    // target_domain_hash does NOT match -> out_domain_match = 0
    let attr_hi: Field = 111;
    let attr_lo: Field = 222;
    let link_rand_x: Field = 333;
    let scope: Field = 0;
    let epoch: Field = 0;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let wrong_target = decode_domain(attr_hi + 1, attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let tag = pedersen_hash([link_rand_x, scope, epoch]);
    let digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);

    main(
        c.x,
        c.y,
        test_message_hash(),
        wrong_target,
        scope,
        epoch,
        attr_hi,
        attr_lo,
        link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        tag,
        0,
        digest,
    );
}

#[test(should_fail)]
fn test_wrong_commitment() {
    let attr_hi: Field = 1;
    let attr_lo: Field = 2;
    let link_rand_x: Field = 3;
    let scope: Field = 4;
    let epoch: Field = 5;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let target = decode_domain(attr_hi, attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let tag = pedersen_hash([link_rand_x, scope, epoch]);
    let digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);

    // Tamper the commitment -- commit_attributes_eq must fail.
    main(
        c.x + 1,
        c.y,
        test_message_hash(),
        target,
        scope,
        epoch,
        attr_hi,
        attr_lo,
        link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        tag,
        1,
        digest,
    );
}

#[test(should_fail)]
fn test_wrong_pk_sig() {
    let attr_hi: Field = 1;
    let attr_lo: Field = 2;
    let link_rand_x: Field = 3;
    let scope: Field = 4;
    let epoch: Field = 5;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let target = decode_domain(attr_hi, attr_lo);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let tag = pedersen_hash([link_rand_x, scope, epoch]);
    let digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);

    let mut bad_sig = test_signature();
    bad_sig[0] ^= 0xFF;

    // Signature does not match the public key -> verify_device_binding fails.
    main(
        c.x,
        c.y,
        test_message_hash(),
        target,
        scope,
        epoch,
        attr_hi,
        attr_lo,
        link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        bad_sig,
        tag,
        1,
        digest,
    );
}
