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
            assert(
                out_nationality[i] == mrz_data[MRZ_LINE_LEN + 10 + i],
                "Nationality mismatch",
            );
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

        let curr_yy: u16 = (current_date[0] - 48) as u16 * 10
            + (current_date[1] - 48) as u16;
        let curr_mm: u16 = (current_date[2] - 48) as u16 * 10
            + (current_date[3] - 48) as u16;
        let curr_dd: u16 = (current_date[4] - 48) as u16 * 10
            + (current_date[5] - 48) as u16;

        // Calculate age (2-digit year)
        let mut age: u16 = 0;
        if curr_yy >= birth_yy {
            age = curr_yy - birth_yy;
        } else {
            age = 100 + curr_yy - birth_yy;
        }

        // Adjust if birthday hasn't occurred yet this year
        let birthday_passed = (curr_mm > birth_mm)
            | ((curr_mm == birth_mm) & (curr_dd >= birth_dd));

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
            assert(
                out_name[i] == mrz_data[5 + i],
                "Name mismatch",
            );
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

    mrz[0] = 80;  // P
    mrz[1] = 60;  // <
    mrz[2] = 85;  // U
    mrz[3] = 84;  // T
    mrz[4] = 79;  // O
    mrz[5] = 68;  // D
    mrz[6] = 79;  // O
    mrz[7] = 69;  // E
    mrz[8] = 60;  // <
    mrz[9] = 60;  // <
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
        true,  // disclose nationality
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

    mrz[0] = 80;  // P
    mrz[1] = 60;  // <

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
        true,  // disclose age
        false, // don't disclose name
        18,    // must be >= 18
        current_date,
        [0; 3],   // nationality hidden
        [0; 39],  // name hidden
        true,     // is older than 18 (age = 25)
    );
}
