use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_X509};
use openac_core::device::verify_device_binding;
use openac_core::predicate::decode_domain;
use openac_core::profile::{compute_link_tag_with_mode, compute_show_challenge_digest_v2};

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
//   * nonce_hash is [u8; 32]; the helpers in openac_core::profile compress it
//     to two Fields via hash_to_fields (Field cannot fit 256 bits).
//
// Issue P1-9 (2026-04-28):
//   * Challenge digest now binds the credential commitment via
//     `compute_show_challenge_digest_v2`. Without the commitment in the
//     transcript, a presentation under one credential could be replayed
//     against a different credential that happened to share (link_rand,
//     scope, epoch).
//   * Added `link_mode` public input + `compute_link_tag_with_mode` so this
//     circuit supports the same unlinkable mode as `openac_core::show`. The
//     unlinkable case forces `link_scope == 0` and `out_link_tag == 0`.

fn main(
    // === PUBLIC ===
    in_commitment_x509_x: pub Field,
    in_commitment_x509_y: pub Field,
    nonce_hash: pub [u8; 32],
    target_domain_hash: pub Field,
    link_mode: pub bool,
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

    // 4. Scoped link tag with explicit unlinkable-mode support (Issue P1-9).
    //    The shared helper enforces zero-tag in unlinkable mode; here we also
    //    require zero link_scope so callers cannot smuggle a session context
    //    while pretending to be unlinkable.
    if !link_mode {
        assert(link_scope == 0, "Unlinkable mode requires zero scope");
    }
    let expected_link_tag = compute_link_tag_with_mode(link_rand_x, link_scope, epoch, link_mode);
    assert(out_link_tag == expected_link_tag, "Link tag mismatch");

    // 5. Challenge digest binds the verifier's nonce to this presentation.
    //    Issue P1-9: also fold the credential commitment so a tampered nonce
    //    paired with a re-randomised commitment cannot reuse the digest.
    let expected_challenge_digest = compute_show_challenge_digest_v2(
        nonce_hash,
        in_commitment_x509_x,
        in_commitment_x509_y,
        link_rand_x,
    );
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

struct X509Fixture {
    c_x: Field,
    c_y: Field,
    target_domain: Field,
    link_tag_linkable: Field,
    challenge_digest: Field,
    attr_hi: Field,
    attr_lo: Field,
    link_rand_x: Field,
    scope: Field,
    epoch: Field,
}

fn make_fixture(
    attr_hi: Field,
    attr_lo: Field,
    link_rand_x: Field,
    scope: Field,
    epoch: Field,
) -> X509Fixture {
    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let target = decode_domain(attr_hi, attr_lo);
    let link_tag = compute_link_tag_with_mode(link_rand_x, scope, epoch, true);
    let digest = compute_show_challenge_digest_v2(test_message_hash(), c.x, c.y, link_rand_x);
    X509Fixture {
        c_x: c.x,
        c_y: c.y,
        target_domain: target,
        link_tag_linkable: link_tag,
        challenge_digest: digest,
        attr_hi,
        attr_lo,
        link_rand_x,
        scope,
        epoch,
    }
}

#[test]
fn test_valid_show_linkable() {
    let f = make_fixture(1, 2, 3, 4, 5);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        true,
        f.scope,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag_linkable,
        1,
        f.challenge_digest,
    );
}

#[test]
fn test_valid_show_unlinkable() {
    // Issue P1-9: x509_show now supports unlinkable mode -- link_scope and
    // out_link_tag must both be 0 when link_mode = false.
    let f = make_fixture(1, 2, 3, 0, 5);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        false,
        0,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        0,
        1,
        f.challenge_digest,
    );
}

#[test]
fn test_domain_match_true() {
    let f = make_fixture(111, 222, 333, 0, 0);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        false,
        0,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        0,
        1,
        f.challenge_digest,
    );
}

#[test]
fn test_domain_match_false() {
    let f = make_fixture(111, 222, 333, 0, 0);
    let wrong_target = decode_domain(f.attr_hi + 1, f.attr_lo);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        wrong_target,
        false,
        0,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        0,
        0,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_commitment() {
    let f = make_fixture(1, 2, 3, 4, 5);
    main(
        f.c_x + 1,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        true,
        f.scope,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag_linkable,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_pk_sig() {
    let f = make_fixture(1, 2, 3, 4, 5);
    let mut bad_sig = test_signature();
    bad_sig[0] ^= 0xFF;
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        true,
        f.scope,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        bad_sig,
        f.link_tag_linkable,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_link_scope_breaks_link_tag() {
    let f = make_fixture(1, 2, 3, 4, 5);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        true,
        f.scope + 1, // TAMPERED scope without recomputing tag
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag_linkable,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_epoch_breaks_link_tag() {
    let f = make_fixture(1, 2, 3, 4, 5);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        true,
        f.scope,
        f.epoch + 42, // TAMPERED epoch without recomputing tag
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag_linkable,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_unlinkable_mode_rejects_nonzero_scope() {
    // Issue P1-9: link_mode = false must enforce link_scope == 0 in-circuit.
    // A prover that pretends to be unlinkable while supplying a non-zero
    // scope must be rejected by the circuit, not just by off-chain policy.
    let f = make_fixture(1, 2, 3, 0, 5);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        false,
        7, // Non-zero scope contradicts link_mode = false
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        0,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_unlinkable_mode_rejects_nonzero_tag() {
    // Issue P1-9 companion: with link_mode = false and link_scope = 0, a
    // non-zero out_link_tag must still be rejected.
    let f = make_fixture(1, 2, 3, 0, 5);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        false,
        0,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        99, // Non-zero tag contradicts link_mode = false
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_challenge_digest_rejects_wrong_commitment_binding() {
    // Issue P1-9 (commitment binding): the digest must reject a
    // pre-recomputed digest derived from a different commitment. Build the
    // expected digest against (c.x + 1) so the in-circuit recomputation
    // diverges and the assert fires.
    let f = make_fixture(1, 2, 3, 4, 5);
    let bogus_digest =
        compute_show_challenge_digest_v2(test_message_hash(), f.c_x + 1, f.c_y, f.link_rand_x);
    main(
        f.c_x,
        f.c_y,
        test_message_hash(),
        f.target_domain,
        true,
        f.scope,
        f.epoch,
        f.attr_hi,
        f.attr_lo,
        f.link_rand_x,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag_linkable,
        1,
        bogus_digest,
    );
}
