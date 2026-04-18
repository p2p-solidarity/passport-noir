use std::hash::pedersen_hash;

use openac_core::commit::{
    assert_commitment_eq, commit_attributes_v3, DOMAIN_PASSPORT, DOMAIN_SDJWT, DOMAIN_X509,
    hash_to_fields,
};
use openac_core::device::verify_device_binding;
use openac_core::predicate::{age_from_attr, sdjwt_predicate_check};
use openac_core::profile::{derive_sdjwt_link_rand, derive_x509_link_rand};

// Composite OpenAC Show Circuit (Path A, v1)
//
// Spec: spec/x509-circuits.md section 7.
//
// Proves the prover holds two Pedersen v3 commitments -- one passport and one
// aux credential (X.509 OR SD-JWT, controlled by the public `aux_domain`) --
// both bound to the SAME Secure Enclave key (pk_digest). The pair therefore
// belongs to one device and can be presented together without revealing
// contents.
//
// Responsibilities (per spec sec 7):
//   1. Run a single ECDSA-P256 verification over `nonce_hash` to derive
//      pk_digest (openac_core::device).
//   2. Derive the aux link randomness from link_rand_p via the shared helper
//      keyed on `aux_domain` -- SALT_X509 for X.509, SALT_SDJWT for SD-JWT --
//      so we never fork the derivation rule.
//   3. Re-open both commitments with the shared pk_digest.
//   4. Emit two boolean predicates from openac_core::predicate:
//        * out_is_older: age_from_attr(passport attrs vs. current date) >=
//          age_threshold.
//        * out_aux_predicate: pedersen_hash([a_attr_hi, a_attr_lo]) ==
//          target_aux_hash. (Spec overloads this as "opened aux attr hash"
//          regardless of credential flavor.)
//   5. Publish a scoped link tag (link_scope, epoch are public per spec) keyed
//      on link_rand_p so the verifier can recognise the bundle under that
//      scope/epoch without linking to other scopes.
//   6. Publish a challenge digest binding `nonce_hash` to the presentation.

fn field_to_u32(f: Field) -> u32 {
    // Range-check the threshold/date fields fit in 32 bits and decode LE.
    let bytes = f.to_le_bytes::<4>();
    (bytes[0] as u32)
        + (bytes[1] as u32) * 256
        + (bytes[2] as u32) * 65536
        + (bytes[3] as u32) * 16777216
}

fn main(
    // === PUBLIC ===
    in_commitment_passport_x: pub Field,
    in_commitment_passport_y: pub Field,
    in_commitment_aux_x: pub Field,
    in_commitment_aux_y: pub Field,
    aux_domain: pub Field,
    nonce_hash: pub [u8; 32],
    age_threshold: pub Field,
    current_year: pub Field,
    current_month: pub Field,
    current_day: pub Field,
    target_aux_hash: pub Field,
    link_scope: pub Field,
    epoch: pub Field,
    // === PRIVATE ===
    p_attr_hi: Field,
    p_attr_lo: Field,
    link_rand_p: Field,
    a_attr_hi: Field,
    a_attr_lo: Field,
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    signature: [u8; 64],
    // === PUBLIC OUTPUTS ===
    out_link_tag: pub Field,
    out_is_older: pub Field,
    out_aux_predicate: pub Field,
    out_challenge_digest: pub Field,
) {
    // aux_domain must be one of the supported credential tags.
    let is_x509 = aux_domain == DOMAIN_X509;
    let is_sdjwt = aux_domain == DOMAIN_SDJWT;
    assert(is_x509 | is_sdjwt, "aux_domain must be DOMAIN_X509 or DOMAIN_SDJWT");

    // 1. ECDSA once -- same pk_digest rides both commitments.
    let pk_digest = verify_device_binding(enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // 2. Derive the aux link randomness from the root link_rand_p using the
    //    credential-specific salt (openac_core::profile::derive_*_link_rand).
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let link_rand_s = derive_sdjwt_link_rand(link_rand_p);
    let link_rand_a = if is_x509 { link_rand_x } else { link_rand_s };

    // 3. Re-open both commitments with the SAME pk_digest.
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        pk_digest,
        link_rand_p,
    );
    assert_commitment_eq(c_p, in_commitment_passport_x, in_commitment_passport_y);

    let c_a = commit_attributes_v3(aux_domain, a_attr_hi, a_attr_lo, pk_digest, link_rand_a);
    assert_commitment_eq(c_a, in_commitment_aux_x, in_commitment_aux_y);

    // 4. Predicates (shared helpers; see openac_core::predicate).
    let threshold_u32 = field_to_u32(age_threshold);
    let current_year_u32 = field_to_u32(current_year);
    let current_month_u32 = field_to_u32(current_month);
    let current_day_u32 = field_to_u32(current_day);
    let expected_is_older = age_from_attr(
        p_attr_hi,
        p_attr_lo,
        current_year_u32,
        current_month_u32,
        current_day_u32,
        threshold_u32,
    );
    assert(out_is_older == expected_is_older, "Age predicate mismatch");
    assert((out_is_older * (out_is_older - 1)) == 0, "out_is_older must be boolean (0 or 1)");

    let expected_aux_predicate = sdjwt_predicate_check(a_attr_hi, a_attr_lo, target_aux_hash);
    assert(out_aux_predicate == expected_aux_predicate, "Aux predicate mismatch");
    assert(
        (out_aux_predicate * (out_aux_predicate - 1)) == 0,
        "out_aux_predicate must be boolean (0 or 1)",
    );

    // 5. Link tag keyed on link_rand_p (root) under the public (scope, epoch).
    let expected_link_tag = pedersen_hash([link_rand_p, link_scope, epoch]);
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

// Build a packed passport profile (attr_hi, attr_lo) for a known birth date.
// Must stay in sync with openac_core::profile::pack_passport_profile.
fn make_passport_attrs(birth_year: u32) -> (Field, Field) {
    openac_core::profile::pack_passport_profile(
        [0xAA; 32],
        [0xBB; 32],
        birth_year,
        1,
        1,
        [84, 87, 78],
    )
}

struct CompositeFixture {
    p_attr_hi: Field,
    p_attr_lo: Field,
    a_attr_hi: Field,
    a_attr_lo: Field,
    link_rand_p: Field,
    link_scope: Field,
    epoch: Field,
    c_p_x: Field,
    c_p_y: Field,
    c_a_x: Field,
    c_a_y: Field,
    target_aux_hash: Field,
    link_tag: Field,
    challenge_digest: Field,
}

fn make_fixture(aux_domain: Field, birth_year: u32) -> CompositeFixture {
    let (p_attr_hi, p_attr_lo) = make_passport_attrs(birth_year);
    let a_attr_hi: Field = 11;
    let a_attr_lo: Field = 22;
    let link_rand_p: Field = 777;
    let link_scope: Field = 100;
    let epoch: Field = 2026;

    let pk_digest = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let link_rand_a = if aux_domain == DOMAIN_X509 {
        derive_x509_link_rand(link_rand_p)
    } else {
        derive_sdjwt_link_rand(link_rand_p)
    };
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        pk_digest,
        link_rand_p,
    );
    let c_a = commit_attributes_v3(aux_domain, a_attr_hi, a_attr_lo, pk_digest, link_rand_a);
    let target_aux_hash = pedersen_hash([a_attr_hi, a_attr_lo]);
    let link_tag = pedersen_hash([link_rand_p, link_scope, epoch]);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);

    CompositeFixture {
        p_attr_hi,
        p_attr_lo,
        a_attr_hi,
        a_attr_lo,
        link_rand_p,
        link_scope,
        epoch,
        c_p_x: c_p.x,
        c_p_y: c_p.y,
        c_a_x: c_a.x,
        c_a_y: c_a.y,
        target_aux_hash,
        link_tag,
        challenge_digest,
    }
}

#[test]
fn test_composite_valid_x509() {
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test]
fn test_composite_valid_sdjwt() {
    let f = make_fixture(DOMAIN_SDJWT, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_SDJWT,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_invalid_aux_domain() {
    let f = make_fixture(DOMAIN_X509, 2000);
    // DOMAIN_MDL (0x04) is not accepted by composite_show v1.
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        0x04,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_mismatched_pk_digest() {
    // Passport commitment built with a DIFFERENT pk_digest than the one the
    // ECDSA verification produces. The commitment re-open must fail.
    let a_attr_hi: Field = 11;
    let a_attr_lo: Field = 22;
    let link_rand_p: Field = 777;
    let link_scope: Field = 100;
    let epoch: Field = 2026;
    let (p_attr_hi, p_attr_lo) = make_passport_attrs(2000);

    let pk_digest_real = verify_device_binding(
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        test_message_hash(),
    );
    let fake_pk_digest: Field = pk_digest_real + 1;
    let link_rand_x = derive_x509_link_rand(link_rand_p);

    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT,
        p_attr_hi,
        p_attr_lo,
        fake_pk_digest,
        link_rand_p,
    );
    let c_a = commit_attributes_v3(
        DOMAIN_X509,
        a_attr_hi,
        a_attr_lo,
        pk_digest_real,
        link_rand_x,
    );
    let target_aux_hash = pedersen_hash([a_attr_hi, a_attr_lo]);
    let link_tag = pedersen_hash([link_rand_p, link_scope, epoch]);
    let (nonce_hi, nonce_lo) = hash_to_fields(test_message_hash());
    let challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);

    main(
        c_p.x,
        c_p.y,
        c_a.x,
        c_a.y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        target_aux_hash,
        link_scope,
        epoch,
        p_attr_hi,
        p_attr_lo,
        link_rand_p,
        a_attr_hi,
        a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        link_tag,
        1,
        1,
        challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_passport_commitment() {
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x + 1,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_aux_commitment() {
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y + 1,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_epoch_breaks_link_tag() {
    // Bumping the epoch in the public input without updating out_link_tag
    // must be rejected.
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch + 9999,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_age_threshold_predicate() {
    // Birth 2000-01-01 + current 2026-04-18 -> age 26 -> is_older(40) = 0,
    // but the caller asserts 1.
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        40,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_target_aux_hash() {
    // Published target_aux_hash does not match the opened aux attribute pair
    // but the prover claims out_aux_predicate = 1.
    let f = make_fixture(DOMAIN_X509, 2000);
    let wrong_target = pedersen_hash([f.a_attr_hi + 1, f.a_attr_lo]);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        wrong_target,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_swapped_commitment_coordinates() {
    let f = make_fixture(DOMAIN_X509, 2000);
    // Swap passport (x, y) -- must break assert_commitment_eq.
    main(
        f.c_p_y,
        f.c_p_x,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_challenge_digest() {
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest + 1,
    );
}

#[test(should_fail)]
fn test_age_predicate_bound_to_committed_birth_year() {
    // Issue #4: the age predicate must be derived from the committed
    // attr_hi/attr_lo, not from an independent witness. Birth 2010-01-01
    // at current 2026-04-18 -> age 16, so `is_older(18) = 0`. A prover who
    // tries to claim `out_is_older = 1` against the committed 2010 profile
    // must be rejected. If `age_from_attr` secretly read a witness-only
    // placeholder (as the audit suggested), this assertion would slip.
    let f = make_fixture(DOMAIN_X509, 2010);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1, // CLAIM: is_older. Real: 0 (age 16 at threshold 18).
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_tampered_p_attr_breaks_commitment_before_predicate() {
    // Issue #4 companion: if the prover flips p_attr_hi hoping to shift
    // the unpacked birth year, `assert_commitment_eq` must fire first so
    // the predicate never evaluates on an attacker-chosen profile.
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope,
        f.epoch,
        f.p_attr_hi + 1, // TAMPERED attr_hi -> commitment re-open must fail
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}

#[test(should_fail)]
fn test_wrong_link_scope_breaks_link_tag() {
    // Issue #5: `link_scope` is a public input; the link_tag binds
    // (link_rand_p, link_scope, epoch) together, so changing scope without
    // recomputing out_link_tag must be rejected. Confirms the scope policy
    // is enforced by the circuit rather than advisory.
    let f = make_fixture(DOMAIN_X509, 2000);
    main(
        f.c_p_x,
        f.c_p_y,
        f.c_a_x,
        f.c_a_y,
        DOMAIN_X509,
        test_message_hash(),
        18,
        2026,
        4,
        18,
        f.target_aux_hash,
        f.link_scope + 1, // TAMPERED scope, link_tag was computed at the original scope
        f.epoch,
        f.p_attr_hi,
        f.p_attr_lo,
        f.link_rand_p,
        f.a_attr_hi,
        f.a_attr_lo,
        test_pub_key_x(),
        test_pub_key_y(),
        test_signature(),
        f.link_tag,
        1,
        1,
        f.challenge_digest,
    );
}
