use openac_core::commit::{assert_commitment_eq, commit_passport_v3_1, DOMAIN_PASSPORT};
use openac_core::device::verify_device_binding;
use openac_core::predicate::{check_age_above, check_bytes3_eq};
use openac_core::profile::unpack_passport_claims;
use openac_core::show::{HASH_LEN, verify_show};

// Generic OpenAC Show Circuit (v3.1 -- Path A, passport only)
//
// v3.1 changes relative to v3 (spec/upgrade-plan-v3.1.md):
//   * The in-circuit SHA256 challenge digest was REMOVED (P-1/P-2/P-3).
//     Freshness rides on `nonce_hash`: it is a public input the verifier
//     pins against the nonce it issued, and it is the ECDSA-P256 message of
//     the in-circuit device binding. UltraHonk binds all public inputs into
//     the proof transcript, so a separate digest added no security and cost
//     two SHA256 blocks per presentation on the mobile hot path.
//   * `challenge[32]`, `epoch[u8;4]` and `epoch_field` are gone; `epoch` is
//     a single public Field (P-5).
//   * Commitment opening uses arity-8 `commit_passport_v3_1`: full-width
//     SOD / DG1 hashes instead of the truncated 32-byte pack (P-6), and the
//     predicate inputs come from one packed `claims` Field -- no separate
//     birth/nationality witnesses with binding asserts.
//   * Link tag uses the unified credential_type-keyed construction from
//     `openac_core::show` (P-4 / HIGH-4).
//
// Issue P1-8 (2026-04-28, retained): `credential_type` is a PUBLIC input and
// asserted equal to `DOMAIN_PASSPORT` in-circuit, so verifiers can require
// passport-only semantics from this circuit. Multi-credential presentations
// live in composite_show.
//
// Linking:
//   Verifier checks: prepare.out_commitment == show.out_commitment
//   Same (claims, sod/dg1 hashes, pk_digest, link_rand) -> same Grumpkin
//   point. Same enclave_pk + fresh verifier nonce -> same pk_digest plus a
//   fresh ECDSA signature proving holder possession of the private key.

/// Evaluate age and nationality predicates, asserting outputs match.
/// When a disclosure flag is false, the corresponding output is pinned to a
/// zero sentinel (CRITICAL-2, 2026-06-10) so a prover cannot publish forged
/// values through unconstrained outputs.
fn evaluate_predicates(
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    nationality: [u8; 3],
    current_year: u32,
    current_month: u32,
    current_day: u32,
    age_threshold: u32,
    disclose_age: bool,
    disclose_nationality: bool,
    out_is_older: bool,
    out_nationality: [u8; 3],
) {
    if disclose_age {
        let is_older = check_age_above(
            birth_year,
            birth_month,
            birth_day,
            current_year,
            current_month,
            current_day,
            age_threshold,
        );
        assert(is_older == out_is_older, "Age predicate output mismatch");
    } else {
        // Security (CRITICAL-2, 2026-06-10): when age is NOT disclosed the
        // public output must be pinned to a sentinel. Otherwise it is a free
        // witness and a prover can publish `out_is_older = true` for an
        // underage holder.
        assert(!out_is_older, "out_is_older must be false when age not disclosed");
    }

    if disclose_nationality {
        assert(check_bytes3_eq(nationality, out_nationality), "Nationality output mismatch");
    } else {
        // Security (CRITICAL-2): pin undisclosed nationality output to zero so
        // a verifier reading the public output cannot be fed an unconstrained
        // (forged) nationality code.
        assert(
            check_bytes3_eq(out_nationality, [0, 0, 0]),
            "out_nationality must be zero when nationality not disclosed",
        );
    }
}

fn main(
    // === Commitment opening witnesses (private, MUST match prepare) ===
    claims: Field,
    sod_hash_hi: Field,
    sod_hash_lo: Field,
    dg1_hash_hi: Field,
    dg1_hash_lo: Field,
    link_rand: Field,
    // === Path A device-binding witnesses (private) ===
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    signature: [u8; 64],
    // === Public inputs ===
    credential_type: pub Field,
    nonce_hash: pub [u8; HASH_LEN],
    link_mode: pub bool,
    link_scope: pub Field,
    epoch: pub Field,
    current_year: pub u32,
    current_month: pub u32,
    current_day: pub u32,
    age_threshold: pub u32,
    disclose_nationality: pub bool,
    disclose_age: pub bool,
    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
    out_link_tag: pub Field,
    out_is_older: pub bool,
    out_nationality: pub [u8; 3],
) {
    // Issue P1-8: lock the circuit to passport credentials.
    assert(
        credential_type == DOMAIN_PASSPORT,
        "openac_show only accepts DOMAIN_PASSPORT credentials",
    );

    // Step 1: In-circuit ECDSA-P256 device binding over the verifier-issued
    // nonce_hash. This is the v3.1 freshness anchor: a stale presentation
    // carries a signature over an old nonce, and the verifier rejects the
    // pinned `nonce_hash` public input before ever reaching the proof.
    let pk_digest = verify_device_binding(enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // Step 2: Re-open the arity-8 v3.1 Pedersen commitment (must match the
    // prepare proof). Full-width SOD / DG1 hashes -- no truncation.
    let commitment = commit_passport_v3_1(
        claims,
        sod_hash_hi,
        sod_hash_lo,
        dg1_hash_hi,
        dg1_hash_lo,
        pk_digest,
        link_rand,
    );
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);

    // Step 3: Unpack the committed claims. `unpack_passport_claims`
    // range-constrains the claims Field, and the values feeding the
    // predicates are exactly the ones the issuer packed at prepare time --
    // no separate witnesses to re-bind.
    let (birth_year, birth_month, birth_day, nationality) = unpack_passport_claims(claims);

    // Step 4: Scoped linking (unified v3.1 tag; unlinkable mode pins zeros).
    verify_show(
        credential_type,
        link_rand,
        link_mode,
        link_scope,
        epoch,
        out_link_tag,
    );

    // Step 5: Predicate evaluation.
    evaluate_predicates(
        birth_year,
        birth_month,
        birth_day,
        nationality,
        current_year,
        current_month,
        current_day,
        age_threshold,
        disclose_age,
        disclose_nationality,
        out_is_older,
        out_nationality,
    );
}

// ============================================================
// Tests
// ============================================================

use openac_core::commit::DOMAIN_X509;
use openac_core::device::pk_digest_from_bytes;
use openac_core::profile::pack_passport_claims;
use openac_core::show::compute_link_tag;
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// Canonical full-width fingerprint fixture (arbitrary but fixed bytes so
/// commitments are reproducible across tests).
fn test_sod_fields() -> (Field, Field) {
    openac_core::commit::hash_to_fields([0xAA; 32])
}

fn test_dg1_fields() -> (Field, Field) {
    openac_core::commit::hash_to_fields([0xBB; 32])
}

/// Build the v3.1 passport commitment for the canonical enclave fixture.
fn test_commitment(claims: Field, link_rand: Field) -> EmbeddedCurvePoint {
    let (sod_hi, sod_lo) = test_sod_fields();
    let (dg1_hi, dg1_lo) = test_dg1_fields();
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    commit_passport_v3_1(claims, sod_hi, sod_lo, dg1_hi, dg1_lo, pk_digest, link_rand)
}

/// Invoke main() with the fixture fingerprints, exposing only the inputs a
/// test wants to vary.
fn invoke_main(
    credential_type: Field,
    claims: Field,
    link_rand: Field,
    signature: [u8; 64],
    nonce_hash: [u8; HASH_LEN],
    link_mode: bool,
    link_scope: Field,
    epoch: Field,
    current_year: u32,
    current_month: u32,
    current_day: u32,
    age_threshold: u32,
    disclose_nationality: bool,
    disclose_age: bool,
    out_commitment_x: Field,
    out_commitment_y: Field,
    out_link_tag: Field,
    out_is_older: bool,
    out_nationality: [u8; 3],
) {
    let (sod_hi, sod_lo) = test_sod_fields();
    let (dg1_hi, dg1_lo) = test_dg1_fields();
    main(
        claims,
        sod_hi,
        sod_lo,
        dg1_hi,
        dg1_lo,
        link_rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        signature,
        credential_type,
        nonce_hash,
        link_mode,
        link_scope,
        epoch,
        current_year,
        current_month,
        current_day,
        age_threshold,
        disclose_nationality,
        disclose_age,
        out_commitment_x,
        out_commitment_y,
        out_link_tag,
        out_is_older,
        out_nationality,
    );
}

/// Canonical P-256 enclave test fixture (matches openac_core::device).
fn test_enclave_pk_x() -> [u8; 32] {
    [
        0x43, 0xa3, 0x93, 0x7c, 0xff, 0x2b, 0xcb, 0x51, 0xd0, 0x93, 0xf0, 0x01, 0x7c, 0x32, 0x99,
        0xef, 0x5f, 0xec, 0x7c, 0x97, 0x16, 0xd5, 0xb9, 0xc6, 0x76, 0xfd, 0xaf, 0x78, 0xc2, 0x0b,
        0x0f, 0x78,
    ]
}

fn test_enclave_pk_y() -> [u8; 32] {
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

/// The nonce_hash the canonical fixture signature was produced over.
fn test_nonce_hash() -> [u8; HASH_LEN] {
    [
        0xd6, 0xe9, 0xef, 0x3f, 0xc3, 0x44, 0x1a, 0xb5, 0x33, 0xb3, 0x84, 0x31, 0xda, 0x4c, 0xa9,
        0x67, 0x49, 0xaf, 0x9a, 0x3e, 0x2f, 0x8e, 0x99, 0x35, 0x38, 0x91, 0xbd, 0xf4, 0x05, 0x94,
        0x5a, 0xde,
    ]
}

fn sample_epoch() -> Field {
    0x20260401
}

#[test]
fn test_show_full_disclosure_linkable() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let epoch = sample_epoch();
    let scope: Field = 99;

    let c = test_commitment(claims, rand);
    let tag = compute_link_tag(DOMAIN_PASSPORT, rand, scope, epoch);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        true,
        scope,
        epoch,
        2026,
        4,
        1,
        18,
        true,
        true, // disclose both
        c.x,
        c.y,
        tag,
        true, // is_older = true (age 26 >= 18)
        [84, 87, 78], // nationality = TWN
    );
}

#[test]
fn test_show_unlinkable_no_disclosure() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        false, // no disclosure
        c.x,
        c.y,
        0, // zero link tag
        false, // age not disclosed
        [0, 0, 0], // nationality not disclosed
    );
}

#[test]
fn test_show_age_only_disclosure() {
    let claims = pack_passport_claims(1990, 6, 15, [85, 83, 65]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        21,
        false,
        true, // age only
        c.x,
        c.y,
        0,
        true, // is_older = true (age 35 >= 21)
        [0, 0, 0], // nationality not disclosed
    );
}

#[test]
fn test_show_nationality_only_disclosure() {
    let claims = pack_passport_claims(2000, 1, 15, [68, 69, 85]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        true,
        false, // nationality only
        c.x,
        c.y,
        0,
        false, // age not disclosed
        [68, 69, 85], // nationality = DEU
    );
}

#[test]
fn test_show_commitment_links_to_prepare() {
    // Same (claims, fingerprints, pk_digest, rand) produces the same Grumpkin
    // point in prepare and show, which is how the verifier links the proofs.
    let claims = pack_passport_claims(1990, 6, 15, [85, 83, 65]);
    let c_prepare = test_commitment(claims, 77);
    let c_show = test_commitment(claims, 77);

    assert(c_prepare.x == c_show.x, "Commitment X must match between prepare and show");
    assert(c_prepare.y == c_show.y, "Commitment Y must match between prepare and show");
}

#[test]
fn test_show_commitment_changes_with_enclave_pk() {
    // Path A property: swapping the enclave pk breaks the commitment link
    // between prepare and show, even when all other inputs stay identical.
    let claims = pack_passport_claims(1990, 6, 15, [85, 83, 65]);
    let (sod_hi, sod_lo) = test_sod_fields();
    let (dg1_hi, dg1_lo) = test_dg1_fields();

    let pk_digest_a = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let mut pk_x_b = test_enclave_pk_x();
    pk_x_b[0] ^= 0x01;
    let pk_digest_b = pk_digest_from_bytes(pk_x_b, test_enclave_pk_y());

    let c_a = commit_passport_v3_1(claims, sod_hi, sod_lo, dg1_hi, dg1_lo, pk_digest_a, 77);
    let c_b = commit_passport_v3_1(claims, sod_hi, sod_lo, dg1_hi, dg1_lo, pk_digest_b, 77);

    assert(c_a.x != c_b.x, "Different enclave pk must yield different v3.1 commitment");
}

// Security regression (CRITICAL-2, 2026-06-10): with disclose_age = false the
// prover must not be able to publish out_is_older = true.
#[test(should_fail_with = "out_is_older must be false when age not disclosed")]
fn test_show_rejects_forged_is_older_when_age_undisclosed() {
    let claims = pack_passport_claims(2010, 1, 15, [84, 87, 78]); // 16yo
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        false, // no disclosure
        c.x,
        c.y,
        0,
        true, // FORGED: claim over-18 without disclosing age
        [0, 0, 0],
    );
}

// Security regression (CRITICAL-2): with disclose_nationality = false the
// nationality output must be pinned to zero, not a forged code.
#[test(should_fail_with = "out_nationality must be zero when nationality not disclosed")]
fn test_show_rejects_forged_nationality_when_undisclosed() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false, // nationality not disclosed
        false,
        c.x,
        c.y,
        0,
        false,
        [85, 83, 65], // FORGED: publish USA while not disclosing nationality
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_age_output() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        true,
        c.x,
        c.y,
        0,
        false, // WRONG: age 26 >= 18 should be true
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_nationality_output() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        true,
        false,
        c.x,
        c.y,
        0,
        false,
        [85, 83, 65], // WRONG: claims USA but committed nationality is TWN
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_commitment() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x + 1, // WRONG X
        c.y,
        0,
        false,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_fails_on_bad_signature() {
    // A tampered ECDSA signature must break verify_device_binding.
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    let mut bad_sig = test_signature();
    bad_sig[0] ^= 0xFF;

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        bad_sig,
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x,
        c.y,
        0,
        false,
        [0, 0, 0],
    );
}

// v3.1 digest-removal regression: freshness is carried by nonce_hash alone,
// so a signature produced over an OLD nonce must not verify against a new
// verifier-issued nonce_hash. This is the in-circuit half of replay
// protection (the verifier-side half pins nonce_hash as a public input).
#[test(should_fail)]
fn test_show_rejects_stale_nonce_signature() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    let mut fresh_nonce = test_nonce_hash();
    fresh_nonce[0] ^= 0x01; // verifier issued a new nonce; signature is stale

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        fresh_nonce,
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x,
        c.y,
        0,
        false,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_rejects_forged_claims() {
    // The commitment binds claims for birth year 2000; a prover supplying a
    // 1980 claims Field (to inflate age) must fail the commitment re-open.
    let committed_claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let forged_claims = pack_passport_claims(1980, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(committed_claims, rand);

    invoke_main(
        DOMAIN_PASSPORT,
        forged_claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        true,
        c.x,
        c.y,
        0,
        true,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_link_tag() {
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let epoch = sample_epoch();
    let scope: Field = 99;
    let c = test_commitment(claims, rand);
    let tag = compute_link_tag(DOMAIN_PASSPORT, rand, scope, epoch);

    invoke_main(
        DOMAIN_PASSPORT,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        true,
        scope + 1, // TAMPERED scope without recomputing tag
        epoch,
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x,
        c.y,
        tag,
        false,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_rejects_non_passport_credential_type() {
    // Issue P1-8: a prover that supplies DOMAIN_X509 must be rejected by the
    // in-circuit DOMAIN_PASSPORT check regardless of commitment validity.
    let claims = pack_passport_claims(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let c = test_commitment(claims, rand);

    invoke_main(
        DOMAIN_X509,
        claims,
        rand,
        test_signature(),
        test_nonce_hash(),
        false,
        0,
        sample_epoch(),
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x,
        c.y,
        0,
        false,
        [0, 0, 0],
    );
}
