use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_X509};
use openac_core::device::verify_device_binding;
use openac_core::predicate::decode_domain;
use openac_core::show::verify_show;

// X.509-only OpenAC Show Circuit (Path A, v3.1)
//
// Spec: spec/x509-circuits.md section 6 + spec/upgrade-plan-v3.1.md.
//
// Responsibilities:
//   1. Re-open the X.509 Pedersen commitment using attributes, shared pk_digest
//      and link_rand_x (derived off-chain from link_rand_p by the caller).
//   2. Verify the enclave ECDSA-P256 signature over `nonce_hash` in-circuit and
//      bind the resulting pk_digest into the commitment opening.
//   3. Evaluate a simple domain predicate: the caller provides the (already
//      hashed) target domain Field; we hash the opened (attr_hi, attr_lo) with
//      pedersen_hash and surface a 0/1 match flag.
//   4. Emit a scoped link tag via the unified openac_core::show construction.
//
// v3.1 changes (2026-06-10):
//   * `out_challenge_digest` REMOVED. Freshness rides on `nonce_hash`, which
//     the verifier pins as a public input and which is the ECDSA message of
//     the device binding -- see openac_core::show header for the full
//     argument. This also deletes the x509-specific Pedersen digest that the
//     Rust verifier could never recompute (mopro "PinnedInProof" dual path).
//   * Link tag switched to `verify_show(DOMAIN_X509, link_rand_x, ...)` -- the
//     same credential_type-keyed construction every show circuit now uses
//     (HIGH-4 namespace unification).

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
) {
    // 1. ECDSA-P256 + pk_digest derivation (openac_core::device).
    let pk_digest = verify_device_binding(enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // 2. Re-open the X.509 commitment with the shared pk_digest bound in.
    let c = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    assert_commitment_eq(c, in_commitment_x509_x, in_commitment_x509_y);

    // 3. Domain predicate. We only surface 0/1; the opened attributes stay
    //    private. The adapter is responsible for packing the domain into
    //    (attr_hi, attr_lo) the same way the verifier packs `target_domain_hash`.
    //
    // VERIFIER CONTRACT (security review HIGH-1, 2026-06-10): a proof with
    // `out_domain_match == 0` is a VALID proof (the holder's domain simply did
    // not match the target). The circuit does not require a match. A relying
    // verifier that wants "domain matched" semantics MUST check
    // `out_domain_match == 1` as an explicit post-proof policy step -- and
    // compare for equality to 1, never `!= 0`, since the boolean constraint
    // only guarantees the value is 0 or 1.
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

    // 4. Scoped link tag -- unified v3.1 construction. Unlinkable mode pins
    //    link_scope == 0 and out_link_tag == 0 in-circuit.
    verify_show(
        DOMAIN_X509,
        link_rand_x,
        link_mode,
        link_scope,
        epoch,
        out_link_tag,
    );
}

// ============================================================
// Tests
// ============================================================
// ECDSA-P256 fixture reused from openac_core::device so the show circuit
// stays on the same canonical vector. Message:
// SHA256("openac_device_binding_test_v2").

use openac_core::show::compute_link_tag;

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
    let link_tag = compute_link_tag(DOMAIN_X509, link_rand_x, scope, epoch);
    X509Fixture {
        c_x: c.x,
        c_y: c.y,
        target_domain: target,
        link_tag_linkable: link_tag,
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
    );
}

#[test]
fn test_valid_show_unlinkable() {
    // link_scope and out_link_tag must both be 0 when link_mode = false.
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
    );
}

#[test(should_fail)]
fn test_unlinkable_mode_rejects_nonzero_scope() {
    // link_mode = false must enforce link_scope == 0 in-circuit.
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
    );
}

#[test(should_fail)]
fn test_unlinkable_mode_rejects_nonzero_tag() {
    // With link_mode = false and link_scope = 0, a non-zero out_link_tag
    // must still be rejected.
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
    );
}

// v3.1 digest-removal regression: a stale device signature (produced over a
// different nonce) must fail the in-circuit ECDSA check -- nonce_hash alone
// carries freshness now.
#[test(should_fail)]
fn test_stale_nonce_signature_rejected() {
    let f = make_fixture(1, 2, 3, 4, 5);
    let mut fresh_nonce = test_message_hash();
    fresh_nonce[0] ^= 0x01;
    main(
        f.c_x,
        f.c_y,
        fresh_nonce,
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
    );
}
