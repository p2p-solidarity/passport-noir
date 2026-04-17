use sha256::digest as sha256_hash;

// Selective Disclosure Circuit
//
// Given verified passport data (DG1 - Machine Readable Zone), proves specific
// attributes (nationality, age >= threshold, name) without revealing the full MRZ.
//
// DG1 MRZ layout (TD3 passport, 88 characters / 2 lines of 44):
//   Line 1: P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<
//   Line 2: L898902C<3UTO6908061F9406236ZE184226B<<<<<14
//
// Offsets (0-indexed in line 2):
//   - Document number:  0..8
//   - Nationality:      10..12  (3-letter ICAO code)
//   - Date of birth:    13..18  (YYMMDD)
//   - Sex:              20      (M/F/<)
//   - Expiry date:      21..26  (YYMMDD)

global MRZ_LINE_LEN: u32 = 44;
global MRZ_TOTAL_LEN: u32 = 88;

fn main(
    // Full MRZ data (private - never revealed)
    mrz_data: [u8; MRZ_TOTAL_LEN],
    // SHA-256 hash of the MRZ (public - ties to data_integrity proof)
    mrz_hash: pub [u8; 32],
    // Disclosure flags (public - what the verifier requested)
    disclose_nationality: pub bool,
    disclose_older_than: pub bool,
    disclose_name: pub bool,
    // Age threshold in years (public)
    age_threshold: pub u8,
    // Current date as YYMMDD for age comparison (public)
    current_date: pub [u8; 6],
    // Disclosed outputs (public - revealed to verifier if flag is set, zero otherwise)
    out_nationality: pub [u8; 3],
    out_name: pub [u8; 39],
    out_is_older: pub bool,
) {
    // 1. Verify MRZ hash matches the committed data
    let computed_hash: [u8; 32] = sha256_hash(mrz_data);
    for i in 0..32 {
        assert(computed_hash[i] == mrz_hash[i], "MRZ hash mismatch");
    }

    // 2. Nationality disclosure (line 2, positions 10..12)
    if disclose_nationality {
        for i in 0..3 {
            assert(out_nationality[i] == mrz_data[MRZ_LINE_LEN + 10 + i], "Nationality mismatch");
        }
    } else {
        for i in 0..3 {
            assert(out_nationality[i] == 0, "Nationality should be hidden");
        }
    }

    // 3. Age verification (line 2, positions 13..18 = YYMMDD of birth)
    if disclose_older_than {
        let birth_yy: u16 = (mrz_data[MRZ_LINE_LEN + 13] - 48) as u16 * 10
            + (mrz_data[MRZ_LINE_LEN + 14] - 48) as u16;
        let birth_mm: u16 = (mrz_data[MRZ_LINE_LEN + 15] - 48) as u16 * 10
            + (mrz_data[MRZ_LINE_LEN + 16] - 48) as u16;
        let birth_dd: u16 = (mrz_data[MRZ_LINE_LEN + 17] - 48) as u16 * 10
            + (mrz_data[MRZ_LINE_LEN + 18] - 48) as u16;

        let curr_yy: u16 = (current_date[0] - 48) as u16 * 10 + (current_date[1] - 48) as u16;
        let curr_mm: u16 = (current_date[2] - 48) as u16 * 10 + (current_date[3] - 48) as u16;
        let curr_dd: u16 = (current_date[4] - 48) as u16 * 10 + (current_date[5] - 48) as u16;

        // Calculate age (2-digit year)
        let mut age: u16 = 0;
        if curr_yy >= birth_yy {
            age = curr_yy - birth_yy;
        } else {
            age = 100 + curr_yy - birth_yy;
        }

        // Adjust if birthday hasn't occurred yet this year
        let birthday_passed =
            (curr_mm > birth_mm) | ((curr_mm == birth_mm) & (curr_dd >= birth_dd));

        if !birthday_passed {
            age = age - 1;
        }

        let is_older = age >= age_threshold as u16;
        assert(out_is_older == is_older, "Age verification mismatch");
    } else {
        assert(!out_is_older, "Age result should be hidden");
    }

    // 4. Name disclosure (line 1, positions 5..43 - surname<<given_names)
    if disclose_name {
        for i in 0..39 {
            assert(out_name[i] == mrz_data[5 + i], "Name mismatch");
        }
    } else {
        for i in 0..39 {
            assert(out_name[i] == 0, "Name should be hidden");
        }
    }
}

#[test]
fn test_nationality_disclosure() {
    let mut mrz: [u8; MRZ_TOTAL_LEN] = [60; MRZ_TOTAL_LEN];

    mrz[0] = 80; // P
    mrz[1] = 60; // <
    mrz[2] = 85; // U
    mrz[3] = 84; // T
    mrz[4] = 79; // O
    mrz[5] = 68; // D
    mrz[6] = 79; // O
    mrz[7] = 69; // E
    mrz[8] = 60; // <
    mrz[9] = 60; // <
    mrz[10] = 74; // J
    mrz[11] = 79; // O
    mrz[12] = 72; // H
    mrz[13] = 78; // N

    // Nationality at 44+10..44+12 = "UTO"
    mrz[54] = 85; // U
    mrz[55] = 84; // T
    mrz[56] = 79; // O

    // DOB at 44+13..44+18 = "900101"
    mrz[57] = 57; // 9
    mrz[58] = 48; // 0
    mrz[59] = 48; // 0
    mrz[60] = 49; // 1
    mrz[61] = 48; // 0
    mrz[62] = 49; // 1

    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    let out_nationality: [u8; 3] = [85, 84, 79]; // UTO
    let out_name: [u8; 39] = [0; 39];

    main(
        mrz,
        mrz_hash,
        true, // disclose nationality
        false, // don't disclose age
        false, // don't disclose name
        18,
        [50, 54, 48, 51, 49, 52], // "260314"
        out_nationality,
        out_name,
        false,
    );
}

#[test]
fn test_age_verification() {
    let mut mrz: [u8; MRZ_TOTAL_LEN] = [60; MRZ_TOTAL_LEN];

    mrz[0] = 80; // P
    mrz[1] = 60; // <

    // DOB at 44+13..44+18 = "000315" (2000-03-15)
    mrz[57] = 48; // 0
    mrz[58] = 48; // 0
    mrz[59] = 48; // 0
    mrz[60] = 51; // 3
    mrz[61] = 49; // 1
    mrz[62] = 53; // 5

    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    // Current date: 2026-03-14, person born 2000-03-15, age 25
    let current_date: [u8; 6] = [50, 54, 48, 51, 49, 52]; // "260314"

    main(
        mrz,
        mrz_hash,
        false, // don't disclose nationality
        true, // disclose age
        false, // don't disclose name
        18, // must be >= 18
        current_date,
        [0; 3], // nationality hidden
        [0; 39], // name hidden
        true, // is older than 18 (age = 25)
    );
}

// Helper: build standard test MRZ with custom fields
fn build_test_mrz(nationality: [u8; 3], dob: [u8; 6], name_bytes: [u8; 39]) -> [u8; MRZ_TOTAL_LEN] {
    let mut mrz: [u8; MRZ_TOTAL_LEN] = [60; MRZ_TOTAL_LEN]; // fill with '<'
    mrz[0] = 80; // P
    mrz[1] = 60; // <
    mrz[2] = 85; // U (issuing country)
    mrz[3] = 84; // T
    mrz[4] = 79; // O
    // Name at positions 5..43
    for i in 0..39 {
        mrz[5 + i] = name_bytes[i];
    }
    // Nationality at line2 positions 10..12 (absolute 54..56)
    mrz[54] = nationality[0];
    mrz[55] = nationality[1];
    mrz[56] = nationality[2];
    // DOB at line2 positions 13..18 (absolute 57..62)
    mrz[57] = dob[0];
    mrz[58] = dob[1];
    mrz[59] = dob[2];
    mrz[60] = dob[3];
    mrz[61] = dob[4];
    mrz[62] = dob[5];
    mrz
}

// DS-3: Name disclosure
#[test]
fn test_name_disclosure() {
    let mut name_bytes: [u8; 39] = [60; 39]; // fill with '<'
    // "DOE<<JOHN"
    name_bytes[0] = 68;
    name_bytes[1] = 79;
    name_bytes[2] = 69; // DOE
    name_bytes[3] = 60;
    name_bytes[4] = 60; // <<
    name_bytes[5] = 74;
    name_bytes[6] = 79;
    name_bytes[7] = 72;
    name_bytes[8] = 78; // JOHN

    let mrz = build_test_mrz(
        [85, 84, 79], // UTO
        [57, 48, 48, 49, 48, 49], // 900101
        name_bytes,
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        false,
        true, // only disclose name
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        name_bytes,
        false,
    );
}

// DS-4: All three disclosures simultaneously
#[test]
fn test_all_disclosures_simultaneously() {
    let mut name_bytes: [u8; 39] = [60; 39];
    name_bytes[0] = 68;
    name_bytes[1] = 79;
    name_bytes[2] = 69; // DOE
    name_bytes[3] = 60;
    name_bytes[4] = 60;
    name_bytes[5] = 74;
    name_bytes[6] = 79;
    name_bytes[7] = 72;
    name_bytes[8] = 78; // JOHN

    let mrz = build_test_mrz(
        [85, 84, 79], // UTO
        [57, 48, 48, 49, 48, 49], // 900101 -> 1990, age 36
        name_bytes,
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        true,
        true,
        true, // all flags on
        18,
        [50, 54, 48, 51, 49, 52], // 260314
        [85, 84, 79], // UTO
        name_bytes,
        true, // age 36 >= 18
    );
}

// DS-5: No disclosure - all flags false, outputs zeroed
#[test]
fn test_no_disclosure() {
    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], [60; 39]);
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        false,
        false,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        [0; 39],
        false,
    );
}

// DS-6: Age exactly at threshold (18th birthday today)
#[test]
fn test_age_exactly_at_threshold() {
    // DOB = 080314 (2008-03-14), current = 260314, age = exactly 18
    let mrz = build_test_mrz(
        [85, 84, 79],
        [48, 56, 48, 51, 49, 52], // "080314"
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        true,
        false,
        18,
        [50, 54, 48, 51, 49, 52], // "260314"
        [0; 3],
        [0; 39],
        true, // exactly 18, >= threshold
    );
}

// DS-7: Age one day below threshold - birthday tomorrow
#[test]
fn test_age_one_day_below_threshold() {
    // DOB = 080315 (2008-03-15), current = 260314, age = 17 years 364 days
    let mrz = build_test_mrz(
        [85, 84, 79],
        [48, 56, 48, 51, 49, 53], // "080315"
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    // out_is_older = false because age < 18
    main(
        mrz,
        mrz_hash,
        false,
        true,
        false,
        18,
        [50, 54, 48, 51, 49, 52], // "260314"
        [0; 3],
        [0; 39],
        false, // NOT older: age 17
    );
}

// DS-9: Wrong MRZ hash - should fail
#[test(should_fail)]
fn test_wrong_mrz_hash_fails() {
    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], [60; 39]);
    // Compute correct hash then tamper it
    let mut bad_hash: [u8; 32] = sha256_hash(mrz);
    bad_hash[0] ^= 0xFF;

    main(
        mrz,
        bad_hash,
        false,
        false,
        false,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        [0; 39],
        false,
    );
}

// DS-10: Wrong nationality output - should fail
#[test(should_fail)]
fn test_wrong_nationality_output_fails() {
    let mrz = build_test_mrz(
        [85, 84, 79], // UTO
        [57, 48, 48, 49, 48, 49],
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        true,
        false,
        false,
        18,
        [50, 54, 48, 51, 49, 52],
        [85, 83, 65], // "USA" - wrong, should be "UTO"
        [0; 39],
        false,
    );
}

// DS-11: Wrong name output - should fail
#[test(should_fail)]
fn test_wrong_name_output_fails() {
    let mut name_bytes: [u8; 39] = [60; 39];
    name_bytes[0] = 68;
    name_bytes[1] = 79;
    name_bytes[2] = 69; // DOE

    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], name_bytes);
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    // Wrong name output
    let mut wrong_name: [u8; 39] = [60; 39];
    wrong_name[0] = 83;
    wrong_name[1] = 77;
    wrong_name[2] = 73; // SMI (not DOE)

    main(
        mrz,
        mrz_hash,
        false,
        false,
        true,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        wrong_name,
        false,
    );
}

// DS-12: Person IS older but out_is_older = false - should fail
#[test(should_fail)]
fn test_wrong_is_older_output_fails() {
    // DOB 900101 -> age 36 >= 18, but we claim out_is_older = false
    let mrz = build_test_mrz(
        [85, 84, 79],
        [57, 48, 48, 49, 48, 49], // "900101"
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        true,
        false,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        [0; 39],
        false, // WRONG: age 36 >= 18, should be true
    );
}

// DS-13: Century rollover - DOB YY=99 -> 1999 (age = 27 in 2026)
#[test]
fn test_century_rollover_dob_1999() {
    // DOB "990101" -> if curr_yy(26) < birth_yy(99): age = 100 + 26 - 99 = 27
    let mrz = build_test_mrz(
        [85, 84, 79],
        [57, 57, 48, 49, 48, 49], // "990101"
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        true,
        false,
        18,
        [50, 54, 48, 51, 49, 52], // "260314"
        [0; 3],
        [0; 39],
        true, // age 27 >= 18
    );
}

// DS-14: Young person - DOB YY=10 -> 2010 (age = 16 in 2026)
#[test]
fn test_young_person_century_2010() {
    // DOB "100101" -> curr_yy(26) >= birth_yy(10): age = 26 - 10 = 16
    let mrz = build_test_mrz(
        [85, 84, 79],
        [49, 48, 48, 49, 48, 49], // "100101"
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        true,
        false,
        18,
        [50, 54, 48, 51, 49, 52], // "260314"
        [0; 3],
        [0; 39],
        false, // age 16 < 18
    );
}

// DS-15: Name with filler characters (< padding)
#[test]
fn test_name_with_filler_characters() {
    // "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" (full 39 bytes with fillers)
    let mut name_bytes: [u8; 39] = [60; 39]; // all '<'
    name_bytes[0] = 68;
    name_bytes[1] = 79;
    name_bytes[2] = 69; // DOE
    name_bytes[3] = 60;
    name_bytes[4] = 60; // <<
    name_bytes[5] = 74;
    name_bytes[6] = 79;
    name_bytes[7] = 72;
    name_bytes[8] = 78; // JOHN

    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], name_bytes);
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    // out_name should include the '<' filler characters as-is
    main(
        mrz,
        mrz_hash,
        false,
        false,
        true,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        name_bytes,
        false,
    );
}

// DS-16: Leap year DOB (2000-02-29)
#[test]
fn test_leap_year_dob() {
    // DOB "000229" -> 2000-02-29, current "260314" -> age 26
    let mrz = build_test_mrz(
        [85, 84, 79],
        [48, 48, 48, 50, 50, 57], // "000229"
        [60; 39],
    );
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    main(
        mrz,
        mrz_hash,
        false,
        true,
        false,
        18,
        [50, 54, 48, 51, 49, 52], // "260314"
        [0; 3],
        [0; 39],
        true, // age 26 >= 18
    );
}

// DS-17: Undisclosed fields must be zeroed
#[test]
fn test_undisclosed_fields_zeroed() {
    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], [60; 39]);
    let mrz_hash: [u8; 32] = sha256_hash(mrz);

    // Only nationality disclosed; name and age must be zeroed
    main(
        mrz,
        mrz_hash,
        true,
        false,
        false, // only nationality
        18,
        [50, 54, 48, 51, 49, 52],
        [85, 84, 79], // correct nationality
        [0; 39], // name must be zero
        false, // is_older must be false
    );
}

// ============================================================
// OpenAC extension: challenge binding for show phase
// ============================================================

global CHALLENGE_BYTES: u32 = 32;
global CHALLENGE_DOMAIN_BYTES: u32 = 14;
global EPOCH_BYTES: u32 = 4;

fn challenge_domain() -> [u8; CHALLENGE_DOMAIN_BYTES] {
    [111, 112, 101, 110, 97, 99, 46, 115, 104, 111, 119, 46, 118, 49]
}

fn compute_challenge_binding(
    challenge: [u8; CHALLENGE_BYTES],
    mrz_hash: [u8; 32],
    epoch: [u8; EPOCH_BYTES],
) -> [u8; 32] {
    let mut preimage: [u8; CHALLENGE_DOMAIN_BYTES + CHALLENGE_BYTES + 32 + EPOCH_BYTES] =
        [0; CHALLENGE_DOMAIN_BYTES + CHALLENGE_BYTES + 32 + EPOCH_BYTES];
    let domain = challenge_domain();

    for i in 0..CHALLENGE_DOMAIN_BYTES {
        preimage[i] = domain[i];
    }

    for i in 0..CHALLENGE_BYTES {
        preimage[CHALLENGE_DOMAIN_BYTES + i] = challenge[i];
    }

    for i in 0..32 {
        preimage[CHALLENGE_DOMAIN_BYTES + CHALLENGE_BYTES + i] = mrz_hash[i];
    }

    for i in 0..EPOCH_BYTES {
        preimage[CHALLENGE_DOMAIN_BYTES + CHALLENGE_BYTES + 32 + i] = epoch[i];
    }

    sha256_hash(preimage)
}

fn main_with_challenge(
    mrz_data: [u8; MRZ_TOTAL_LEN],
    mrz_hash: [u8; 32],
    disclose_nationality: bool,
    disclose_older_than: bool,
    disclose_name: bool,
    age_threshold: u8,
    current_date: [u8; 6],
    out_nationality: [u8; 3],
    out_name: [u8; 39],
    out_is_older: bool,
    challenge: [u8; CHALLENGE_BYTES],
    epoch: [u8; EPOCH_BYTES],
    out_challenge_digest: [u8; 32],
) {
    main(
        mrz_data,
        mrz_hash,
        disclose_nationality,
        disclose_older_than,
        disclose_name,
        age_threshold,
        current_date,
        out_nationality,
        out_name,
        out_is_older,
    );

    let computed = compute_challenge_binding(challenge, mrz_hash, epoch);
    for i in 0..32 {
        assert(computed[i] == out_challenge_digest[i], "Challenge digest mismatch");
    }
}

fn sample_challenge(seed: u8) -> [u8; CHALLENGE_BYTES] {
    let mut out: [u8; CHALLENGE_BYTES] = [0; CHALLENGE_BYTES];
    for i in 0..CHALLENGE_BYTES {
        out[i] = seed + (i as u8);
    }
    out
}

#[test]
fn test_challenge_binding_pass() {
    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], [60; 39]);
    let mrz_hash: [u8; 32] = sha256_hash(mrz);
    let challenge = sample_challenge(7);
    let epoch: [u8; EPOCH_BYTES] = [0x20, 0x26, 0x03, 0x15];
    let out_challenge_digest = compute_challenge_binding(challenge, mrz_hash, epoch);

    main_with_challenge(
        mrz,
        mrz_hash,
        false,
        false,
        false,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        [0; 39],
        false,
        challenge,
        epoch,
        out_challenge_digest,
    );
}

#[test(should_fail)]
fn test_challenge_binding_fails_on_replay_value() {
    let mrz = build_test_mrz([85, 84, 79], [57, 48, 48, 49, 48, 49], [60; 39]);
    let mrz_hash: [u8; 32] = sha256_hash(mrz);
    let challenge = sample_challenge(9);
    let epoch: [u8; EPOCH_BYTES] = [0x20, 0x26, 0x03, 0x15];
    let out_challenge_digest = compute_challenge_binding(challenge, mrz_hash, epoch);

    let mut replayed_challenge = challenge;
    replayed_challenge[0] = replayed_challenge[0] ^ 0x01;

    main_with_challenge(
        mrz,
        mrz_hash,
        false,
        false,
        false,
        18,
        [50, 54, 48, 51, 49, 52],
        [0; 3],
        [0; 39],
        false,
        replayed_challenge,
        epoch,
        out_challenge_digest,
    );
}
