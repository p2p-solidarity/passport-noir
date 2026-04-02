use openac_core::commit::{commit_attributes, assert_commitment_eq};
use openac_core::show::{verify_show, HASH_LEN, EPOCH_BYTES};
use openac_core::predicate::{check_age_above, check_bytes3_eq};

// Generic OpenAC Show Circuit
//
// This circuit is credential-type agnostic. It works with ANY adapter
// (passport, SD-JWT, mDL) because it only needs:
//   1. The same attr_hash and link_rand used in the prepare phase
//   2. The credential_type domain separator
//
// Paper C2 (show relation):
//   "Assert p_i = f_i(m_1, ..., m_n) for all i"  [predicate evaluation]
//   "Assert ECDSA.verify(sigma_nonce, PK_D) = 1"  [device binding - separate circuit]
//
// Linking:
//   Verifier checks: prepare.out_commitment == show.out_commitment
//   Same (credential_type, attr_hash, link_rand) -> same Grumpkin point

fn main(
    // === Commitment re-computation (MUST match prepare) ===
    credential_type: Field,
    attr_hash_hi: Field,
    attr_hash_lo: Field,
    link_rand: Field,

    // === Challenge binding ===
    challenge: [u8; HASH_LEN],

    // === Predicate inputs (private credential attributes) ===
    // Birth date for age check (4-digit year)
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    // Nationality code (3 bytes, e.g., "TWN", "USA", "DEU")
    nationality: [u8; 3],

    // === Public inputs ===
    link_mode: pub bool,
    link_scope: pub Field,
    epoch: pub [u8; EPOCH_BYTES],
    epoch_field: pub Field,

    // Age predicate config
    current_year: pub u32,
    current_month: pub u32,
    current_day: pub u32,
    age_threshold: pub u32,

    // Disclosure flags
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
    // -------------------------------------------------------
    // Step 1: Re-compute Pedersen commitment
    // MUST produce the same Grumpkin point as the prepare proof
    // -------------------------------------------------------
    let commitment = commit_attributes(credential_type, attr_hash_hi, attr_hash_lo, link_rand);
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);

    // -------------------------------------------------------
    // Step 2: Show-phase verification (challenge + linking)
    // -------------------------------------------------------
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

    // -------------------------------------------------------
    // Step 3: Predicate evaluation
    // Paper: "Assert p_i = f_i(m_1, ..., m_n) for all i"
    // -------------------------------------------------------

    // Age predicate
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
    // When disclose_age = false, out_is_older is unconstrained.
    // The verifier MUST ignore out_is_older when disclose_age = false.
    // Asserting a specific value would leak information about the holder's age.

    // Nationality predicate
    if disclose_nationality {
        assert(check_bytes3_eq(nationality, out_nationality), "Nationality output mismatch");
    }
    // When disclose_nationality = false, out_nationality is unconstrained.
    // The verifier MUST ignore out_nationality when disclose_nationality = false.
}

// ============================================================
// Tests
// ============================================================

use openac_core::commit::DOMAIN_PASSPORT;
use openac_core::show::{compute_challenge_digest, compute_link_tag};

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
    let attr_hi: Field = 1000;
    let attr_lo: Field = 2000;
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();
    let scope: Field = 99;

    // Pre-compute expected outputs
    let c = commit_attributes(ctype, attr_hi, attr_lo, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);
    let tag = compute_link_tag(c.x, c.y, scope, epoch_f);

    main(
        ctype, attr_hi, attr_lo, rand,
        challenge,
        2000, 1, 15,          // birth: 2000-01-15
        [84, 87, 78],          // nationality: TWN
        true, scope, epoch, epoch_f,
        2026, 4, 1, 18,        // current date + threshold
        true, true,             // disclose both
        c.x, c.y,
        digest, tag,
        true,                   // is_older = true (age 26 >= 18)
        [84, 87, 78],           // nationality = TWN
    );
}

#[test]
fn test_show_unlinkable_no_disclosure() {
    let ctype = DOMAIN_PASSPORT;
    let attr_hi: Field = 1000;
    let attr_lo: Field = 2000;
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let c = commit_attributes(ctype, attr_hi, attr_lo, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    main(
        ctype, attr_hi, attr_lo, rand,
        challenge,
        2000, 1, 15,
        [84, 87, 78],
        false, 0, epoch, epoch_f,   // unlinkable mode
        2026, 4, 1, 18,
        false, false,                // no disclosure
        c.x, c.y,
        digest, 0,                   // zero link tag
        false,                       // age not disclosed
        [0, 0, 0],                   // nationality not disclosed
    );
}

#[test]
fn test_show_commitment_links_to_prepare() {
    let ctype = DOMAIN_PASSPORT;
    let attr_hi: Field = 5555;
    let attr_lo: Field = 6666;
    let rand: Field = 77;

    // The SAME call in prepare and show produces the SAME Grumpkin point
    let c_prepare = commit_attributes(ctype, attr_hi, attr_lo, rand);
    let c_show = commit_attributes(ctype, attr_hi, attr_lo, rand);

    assert(c_prepare.x == c_show.x);
    assert(c_prepare.y == c_show.y);
}

#[test(should_fail)]
fn test_show_fails_wrong_commitment() {
    let ctype = DOMAIN_PASSPORT;
    let attr_hi: Field = 1000;
    let attr_lo: Field = 2000;
    let rand: Field = 42;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_f = sample_epoch_field();

    let c = commit_attributes(ctype, attr_hi, attr_lo, rand);
    let digest = compute_challenge_digest(c.x, c.y, challenge, epoch);

    // Wrong commitment coordinates
    main(
        ctype, attr_hi, attr_lo, rand,
        challenge,
        2000, 1, 15,
        [84, 87, 78],
        false, 0, epoch, epoch_f,
        2026, 4, 1, 18,
        false, false,
        c.x + 1, c.y,  // WRONG X
        digest, 0,
        false,
        [0, 0, 0],
    );
}
