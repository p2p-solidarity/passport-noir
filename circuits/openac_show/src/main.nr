use openac_core::commit::{assert_commitment_eq, commit_attributes_v3};
use openac_core::device::verify_device_binding;
use openac_core::predicate::{check_age_above, check_bytes3_eq};
use openac_core::profile::unpack_passport_profile;
use openac_core::show::{EPOCH_BYTES, HASH_LEN, verify_show};

// Generic OpenAC Show Circuit (v3 -- Path A, passport only)
//
// v3 changes relative to v2:
//   * commitment re-open uses `commit_attributes_v3` (5-arg Pedersen that binds
//     an enclave pk_digest).
//   * In-circuit ECDSA-P256 device binding: the circuit verifies the enclave's
//     signature over `nonce_hash` (public input) and derives the same
//     `pk_digest` that was bound into the commitment during Prepare. This
//     replaces the external `device_binding` circuit for the passport show
//     flow.
//
// Linking:
//   Verifier checks: prepare.out_commitment == show.out_commitment
//   Same (credential_type, attr_hash, pk_digest, link_rand) -> same Grumpkin point.
//   Same enclave_pk + fresh verifier nonce -> same pk_digest plus a fresh
//   ECDSA signature proving holder possession of the private key.

/// Evaluate age and nationality predicates, asserting outputs match.
/// When a disclosure flag is false, the corresponding output is unconstrained
/// to prevent information leakage.
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
    }

    if disclose_nationality {
        assert(check_bytes3_eq(nationality, out_nationality), "Nationality output mismatch");
    }
}

fn main(
    // === Commitment re-computation (MUST match prepare) ===
    credential_type: Field,
    attr_hash_hi: Field,
    attr_hash_lo: Field,
    link_rand: Field,
    // === Path A device-binding witnesses (private) ===
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    signature: [u8; 64],
    // === Challenge binding ===
    challenge: [u8; HASH_LEN],
    // === Predicate inputs (private credential attributes) ===
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    nationality: [u8; 3],
    // === Public inputs ===
    nonce_hash: pub [u8; HASH_LEN],
    link_mode: pub bool,
    link_scope: pub Field,
    epoch: pub [u8; EPOCH_BYTES],
    epoch_field: pub Field,
    current_year: pub u32,
    current_month: pub u32,
    current_day: pub u32,
    age_threshold: pub u32,
    disclose_nationality: pub bool,
    disclose_age: pub bool,
    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
    out_challenge_digest: pub [u8; HASH_LEN],
    out_link_tag: pub Field,
    out_is_older: pub bool,
    out_nationality: pub [u8; 3],
) {
    // Step 1: In-circuit ECDSA-P256 device binding. Verifies the enclave
    // signature over nonce_hash and returns the canonical pk_digest that
    // must have been bound into the prepare-phase commitment.
    let pk_digest = verify_device_binding(enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // Step 2: Re-compute Pedersen commitment with pk_digest bound in
    // (must match prepare proof's v3 commitment).
    let commitment = commit_attributes_v3(
        credential_type,
        attr_hash_hi,
        attr_hash_lo,
        pk_digest,
        link_rand,
    );
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);

    // Step 2b: Bind predicate inputs to the committed attribute hash. Without
    // this, the prover could produce a valid commitment (and signature) yet
    // feed the predicate evaluator arbitrary birth/nationality values, so
    // "age >= 18" would be proven against witnesses the issuer never signed.
    // `unpack_passport_profile` is the inverse of `pack_passport_profile`
    // used at issuance, so the derived tuple is exactly what was packed into
    // (attr_hash_hi, attr_hash_lo) and therefore into the commitment.
    let (bound_year, bound_month, bound_day, bound_nationality) =
        unpack_passport_profile(attr_hash_hi, attr_hash_lo);
    assert(birth_year == bound_year, "birth_year not bound to commitment attr_hash");
    assert(birth_month == bound_month, "birth_month not bound to commitment attr_hash");
    assert(birth_day == bound_day, "birth_day not bound to commitment attr_hash");
    assert(
        nationality[0] == bound_nationality[0],
        "nationality[0] not bound to commitment attr_hash",
    );
    assert(
        nationality[1] == bound_nationality[1],
        "nationality[1] not bound to commitment attr_hash",
    );
    assert(
        nationality[2] == bound_nationality[2],
        "nationality[2] not bound to commitment attr_hash",
    );

    // Step 3: Show-phase verification (challenge + linking).
    // The challenge digest folds in the commitment coordinates (which now
    // depend on nonce_hash via pk_digest), so `challenge` + `nonce_hash`
    // jointly determine `out_challenge_digest`.
    verify_show(
        commitment.x,
        commitment.y,
        challenge,
        epoch,
        epoch_field,
        link_mode,
        link_scope,
        out_challenge_digest,
        out_link_tag,
    );

    // Step 4: Predicate evaluation.
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

use openac_core::commit::DOMAIN_PASSPORT;
use openac_core::device::pk_digest_from_bytes;
use openac_core::profile::pack_passport_profile;
use openac_core::show::{compute_challenge_digest, compute_link_tag};

/// Test helper: canonical packed passport profile for the ECDSA fixture enclave.
/// The inner hashes are arbitrary but fixed so commitments are reproducible.
fn test_packed_profile(
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    nationality: [u8; 3],
) -> (Field, Field) {
    let sod_hash: [u8; 32] = [0xAA; 32];
    let dg1_hash: [u8; 32] = [0xBB; 32];
    pack_passport_profile(
        sod_hash,
        dg1_hash,
        birth_year,
        birth_month,
        birth_day,
        nationality,
    )
}

/// Canonical P-256 enclave test fixture (matches device_binding/src/main.nr).
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

fn test_nonce_hash() -> [u8; HASH_LEN] {
    [
        0xd6, 0xe9, 0xef, 0x3f, 0xc3, 0x44, 0x1a, 0xb5, 0x33, 0xb3, 0x84, 0x31, 0xda, 0x4c, 0xa9,
        0x67, 0x49, 0xaf, 0x9a, 0x3e, 0x2f, 0x8e, 0x99, 0x35, 0x38, 0x91, 0xbd, 0xf4, 0x05, 0x94,
        0x5a, 0xde,
    ]
}

fn sample_challenge() -> [u8; HASH_LEN] {
    let mut out: [u8; HASH_LEN] = [0; HASH_LEN];
    for i in 0..HASH_LEN {
        out[i] = (i as u8) + 0x40;
    }
    out
}

fn sample_epoch() -> [u8; EPOCH_BYTES] {
    [0x20, 0x26, 0x04, 0x01]
}

fn sample_epoch_field() -> Field {
    0x20260401
}

#[test]
fn test_show_full_disclosure_linkable() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();
    let scope: Field = 99;

    // Pre-compute expected outputs (same pk_digest as the device-binding fixture).
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);
    let tag = compute_link_tag(c.x, c.y, scope, epoch_f);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15, // birth: 2000-01-15
        [84, 87, 78], // nationality: TWN
        test_nonce_hash(),
        true,
        scope,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18, // current date + threshold
        true,
        true, // disclose both
        c.x,
        c.y,
        digest,
        tag,
        true, // is_older = true (age 26 >= 18)
        [84, 87, 78], // nationality = TWN
    );
}

#[test]
fn test_show_unlinkable_no_disclosure() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15,
        [84, 87, 78],
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f, // unlinkable mode
        2026,
        4,
        1,
        18,
        false,
        false, // no disclosure
        c.x,
        c.y,
        digest,
        0, // zero link tag
        false, // age not disclosed
        [0, 0, 0], // nationality not disclosed
    );
}

#[test]
fn test_show_commitment_links_to_prepare() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(1990, 6, 15, [85, 83, 65]);
    let rand: Field = 77;

    // Same (ctype, attrs, pk_digest, rand) produces the same Grumpkin point in
    // prepare and show, which is how the verifier links the two proofs.
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c_prepare = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let c_show = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);

    assert(c_prepare.x == c_show.x, "Commitment X must match between prepare and show");
    assert(c_prepare.y == c_show.y, "Commitment Y must match between prepare and show");
}

#[test]
fn test_show_commitment_changes_with_enclave_pk() {
    // Path A property: swapping the enclave pk breaks the commitment link
    // between prepare and show, even when all other inputs stay identical.
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(1990, 6, 15, [85, 83, 65]);
    let rand: Field = 77;

    let pk_digest_a = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let mut pk_x_b = test_enclave_pk_x();
    pk_x_b[0] ^= 0x01;
    let pk_digest_b = pk_digest_from_bytes(pk_x_b, test_enclave_pk_y());

    let c_a = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest_a, rand);
    let c_b = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest_b, rand);

    assert(c_a.x != c_b.x, "Different enclave pk must yield different v3 commitment");
}

#[test]
fn test_show_age_only_disclosure() {
    let ctype = DOMAIN_PASSPORT;
    // birth 1990-06-15 + USA is packed INTO the commitment so the new binding
    // assertions pass while the test continues to exercise age-only disclosure.
    let (attr_hi, attr_lo) = test_packed_profile(1990, 6, 15, [85, 83, 65]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        1990,
        6,
        15, // birth: 1990-06-15
        [85, 83, 65], // nationality: USA (not disclosed)
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        21, // threshold: 21
        false,
        true, // age only
        c.x,
        c.y,
        digest,
        0,
        true, // is_older = true (age 35 >= 21)
        [0, 0, 0], // nationality not disclosed
    );
}

#[test]
fn test_show_nationality_only_disclosure() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [68, 69, 85]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15,
        [68, 69, 85], // nationality: DEU
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        true,
        false, // nationality only
        c.x,
        c.y,
        digest,
        0,
        false, // age not disclosed
        [68, 69, 85], // nationality = DEU
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_age_output() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15,
        [84, 87, 78],
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        false,
        true,
        c.x,
        c.y,
        digest,
        0,
        false, // WRONG: age 26 >= 18 should be true
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_nationality_output() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15,
        [84, 87, 78], // actual: TWN
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        true,
        false,
        c.x,
        c.y,
        digest,
        0,
        false,
        [85, 83, 65], // WRONG: claims USA but actual is TWN
    );
}

#[test(should_fail)]
fn test_show_fails_wrong_commitment() {
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    // Wrong commitment coordinates
    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15,
        [84, 87, 78],
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x + 1,
        c.y, // WRONG X
        digest,
        0,
        false,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_fails_on_bad_signature() {
    // Path A negative test: a tampered ECDSA signature must break
    // verify_device_binding and prevent the show proof from succeeding.
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    let mut bad_sig = test_signature();
    bad_sig[0] ^= 0xFF;

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        bad_sig,
        challenge,
        2000,
        1,
        15,
        [84, 87, 78],
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        false,
        false,
        c.x,
        c.y,
        digest,
        0,
        false,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_rejects_forged_birth_year() {
    // Core security property for issue #1: the commitment binds birth year to
    // 2000, but the prover tries to pass 1980 as the age witness (so 'age >=
    // 18' would pass for any threshold). Binding assertion must reject this.
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        1980, // FORGED: attr_hash commits to 2000, witness claims 1980
        1,
        15,
        [84, 87, 78],
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        false,
        true,
        c.x,
        c.y,
        digest,
        0,
        true,
        [0, 0, 0],
    );
}

#[test(should_fail)]
fn test_show_rejects_forged_nationality() {
    // Same attack surface as forged birth year, but targeting nationality.
    let ctype = DOMAIN_PASSPORT;
    let (attr_hi, attr_lo) = test_packed_profile(2000, 1, 15, [84, 87, 78]);
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype,
        attr_hi,
        attr_lo,
        rand,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        test_signature(),
        challenge,
        2000,
        1,
        15,
        [85, 83, 65], // FORGED: attr_hash commits to TWN, witness claims USA
        test_nonce_hash(),
        false,
        0,
        epoch,
        epoch_f,
        2026,
        4,
        1,
        18,
        true,
        false,
        c.x,
        c.y,
        digest,
        0,
        false,
        [85, 83, 65],
    );
}
