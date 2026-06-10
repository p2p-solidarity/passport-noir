use sha256::digest;

// Data Integrity Verifier (DG Hash Chain)
//
// Verifies that passport data groups (DG1, DG2, etc.) hash correctly
// into the Security Object Document (SOD). This ensures the passport
// data has not been tampered with.
//
// ICAO 9303 specifies that each data group is individually hashed,
// and the collection of hashes is stored in the SOD's LDS Security Object.
//
// SOD hash format (hard constraint, deviates from ICAO 9303):
//   sod_hash = SHA256(dg0_hash || dg1_hash || dg2_hash || dg3_hash)
// Each slot is 32 bytes; unused slots (when dg_count < MAX_DG_COUNT) are
// zero-padded. This is raw concatenation, NOT the ICAO 9303 LDS Security
// Object's TLV-encoded signedAttrs. Callers (iOS pipeline + passport_verifier)
// must normalize NFC chip data to this layout before consuming this circuit.

// Maximum number of data groups we support (ICAO defines up to 16)
global MAX_DG_COUNT: u32 = 4;
// Maximum bytes per data group content for this circuit
global MAX_DG_SIZE: u32 = 512;

fn main(
    // Number of data groups actually present (1..MAX_DG_COUNT)
    dg_count: u8,
    // Raw data group contents (padded to MAX_DG_SIZE each)
    dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT],
    // Actual length of each data group (for proper hashing)
    dg_lengths: [u32; MAX_DG_COUNT],
    // Expected SHA-256 hashes from the SOD for each data group
    expected_dg_hashes: pub [[u8; 32]; MAX_DG_COUNT],
    // Combined hash of all DG hashes (the value signed by DSC)
    sod_hash: pub [u8; 32],
) {
    assert(dg_count as u32 <= MAX_DG_COUNT, "Too many data groups");
    assert(dg_count > 0, "Must have at least one data group");

    // Verify each data group's hash matches the SOD
    let mut combined_preimage: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];

    for i in 0..MAX_DG_COUNT {
        if (i as u8) < dg_count {
            // Extract the actual DG content up to its real length
            let mut dg_data: [u8; MAX_DG_SIZE] = [0; MAX_DG_SIZE];
            let len = dg_lengths[i];
            assert(len <= MAX_DG_SIZE as u32, "DG length exceeds maximum");

            for j in 0..MAX_DG_SIZE {
                if (j as u32) < len {
                    dg_data[j] = dg_contents[i][j];
                }
            }

            // Hash the data group content
            let computed_hash: [u8; 32] = digest(dg_data);

            // Compare with the expected hash from SOD
            for k in 0..32 {
                assert(computed_hash[k] == expected_dg_hashes[i][k], "Data group hash mismatch");
            }

            // Accumulate into combined preimage for SOD hash
            for k in 0..32 {
                combined_preimage[i * 32 + k] = computed_hash[k];
            }
        }
    }

    // Verify combined hash matches the SOD hash
    let computed_sod_hash: [u8; 32] = digest(combined_preimage);
    for i in 0..32 {
        assert(computed_sod_hash[i] == sod_hash[i], "SOD combined hash mismatch");
    }
}

#[test]
fn test_single_dg() {
    // Test with a single data group
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    // Simple test data: "Hello"
    dg_contents[0][0] = 72; // H
    dg_contents[0][1] = 101; // e
    dg_contents[0][2] = 108; // l
    dg_contents[0][3] = 108; // l
    dg_contents[0][4] = 111; // o

    let dg_lengths: [u32; MAX_DG_COUNT] = [5, 0, 0, 0];

    // Compute expected hash of padded DG (512 bytes, first 5 are "Hello", rest 0)
    let mut padded: [u8; MAX_DG_SIZE] = [0; MAX_DG_SIZE];
    padded[0] = 72;
    padded[1] = 101;
    padded[2] = 108;
    padded[3] = 108;
    padded[4] = 111;
    let dg0_hash: [u8; 32] = digest(padded);

    let mut expected_dg_hashes: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected_dg_hashes[0] = dg0_hash;

    // Combined preimage: dg0_hash + zeros for unused DGs
    let mut combined: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    for i in 0..32 {
        combined[i] = dg0_hash[i];
    }
    let sod_hash: [u8; 32] = digest(combined);

    main(1, dg_contents, dg_lengths, expected_dg_hashes, sod_hash);
}

// Helper: build a padded DG and its hash
fn make_dg_padded(content: [u8; MAX_DG_SIZE]) -> [u8; 32] {
    digest(content)
}

// Helper: compute sod_hash from 4 DG hashes
fn compute_sod_hash(h0: [u8; 32], h1: [u8; 32], h2: [u8; 32], h3: [u8; 32]) -> [u8; 32] {
    let mut combined: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    for i in 0..32 {
        combined[i] = h0[i];
        combined[32 + i] = h1[i];
        combined[64 + i] = h2[i];
        combined[96 + i] = h3[i];
    }
    digest(combined)
}

// DI-2: Two data groups
#[test]
fn test_two_dgs() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    // DG0: "Hello"
    dg_contents[0][0] = 72;
    dg_contents[0][1] = 101;
    dg_contents[0][2] = 108;
    dg_contents[0][3] = 108;
    dg_contents[0][4] = 111;
    // DG1: "World"
    dg_contents[1][0] = 87;
    dg_contents[1][1] = 111;
    dg_contents[1][2] = 114;
    dg_contents[1][3] = 108;
    dg_contents[1][4] = 100;

    let dg_lengths: [u32; MAX_DG_COUNT] = [5, 5, 0, 0];

    let dg0_hash = make_dg_padded(dg_contents[0]);
    let dg1_hash = make_dg_padded(dg_contents[1]);
    let zero_hash: [u8; 32] = [0; 32];

    let mut expected_dg_hashes: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected_dg_hashes[0] = dg0_hash;
    expected_dg_hashes[1] = dg1_hash;

    let sod_hash = compute_sod_hash(dg0_hash, dg1_hash, zero_hash, zero_hash);
    main(2, dg_contents, dg_lengths, expected_dg_hashes, sod_hash);
}

// DI-3: Three data groups
#[test]
fn test_three_dgs() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 65; // "A"
    dg_contents[1][0] = 66; // "B"
    dg_contents[2][0] = 67; // "C"

    let dg_lengths: [u32; MAX_DG_COUNT] = [1, 1, 1, 0];

    let h0 = make_dg_padded(dg_contents[0]);
    let h1 = make_dg_padded(dg_contents[1]);
    let h2 = make_dg_padded(dg_contents[2]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    expected[1] = h1;
    expected[2] = h2;

    let sod_hash = compute_sod_hash(h0, h1, h2, zero);
    main(3, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-4: Maximum four data groups
#[test]
fn test_max_four_dgs() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 49; // "1"
    dg_contents[1][0] = 50; // "2"
    dg_contents[2][0] = 51; // "3"
    dg_contents[3][0] = 52; // "4"

    let dg_lengths: [u32; MAX_DG_COUNT] = [1, 1, 1, 1];

    let h0 = make_dg_padded(dg_contents[0]);
    let h1 = make_dg_padded(dg_contents[1]);
    let h2 = make_dg_padded(dg_contents[2]);
    let h3 = make_dg_padded(dg_contents[3]);

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    expected[1] = h1;
    expected[2] = h2;
    expected[3] = h3;

    let sod_hash = compute_sod_hash(h0, h1, h2, h3);
    main(4, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-5: DG at maximum size (512 bytes)
#[test]
fn test_max_size_dg() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    // Fill DG0 with pattern: byte index mod 256
    for i in 0..MAX_DG_SIZE {
        dg_contents[0][i] = (i % 256) as u8;
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [512, 0, 0, 0];

    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    let sod_hash = compute_sod_hash(h0, zero, zero, zero);
    main(1, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-6: Various DG lengths (1, 100, 256, 512)
#[test]
fn test_various_dg_lengths() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    // DG0: 1 byte
    dg_contents[0][0] = 0xFF;
    // DG1: 100 bytes of 0xAB
    for i in 0..100 {
        dg_contents[1][i] = 0xAB;
    }
    // DG2: 256 bytes of sequential
    for i in 0..256 {
        dg_contents[2][i] = i as u8;
    }
    // DG3: 512 bytes of 0x42
    for i in 0..MAX_DG_SIZE {
        dg_contents[3][i] = 0x42;
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [1, 100, 256, 512];

    let h0 = make_dg_padded(dg_contents[0]);
    let h1 = make_dg_padded(dg_contents[1]);
    let h2 = make_dg_padded(dg_contents[2]);
    let h3 = make_dg_padded(dg_contents[3]);

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    expected[1] = h1;
    expected[2] = h2;
    expected[3] = h3;

    let sod_hash = compute_sod_hash(h0, h1, h2, h3);
    main(4, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-7: Wrong expected hash - should fail
#[test(should_fail)]
fn test_wrong_expected_hash_fails() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 72;
    dg_contents[0][1] = 101;
    dg_contents[0][2] = 108;
    dg_contents[0][3] = 108;
    dg_contents[0][4] = 111;

    let dg_lengths: [u32; MAX_DG_COUNT] = [5, 0, 0, 0];

    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    // Tamper the expected hash
    let mut bad_hash = h0;
    bad_hash[0] ^= 0xFF;

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = bad_hash;

    let sod_hash = compute_sod_hash(h0, zero, zero, zero);
    main(1, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-8: Wrong SOD hash - should fail
#[test(should_fail)]
fn test_wrong_sod_hash_fails() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 72;
    dg_contents[0][1] = 101;
    dg_contents[0][2] = 108;
    dg_contents[0][3] = 108;
    dg_contents[0][4] = 111;

    let dg_lengths: [u32; MAX_DG_COUNT] = [5, 0, 0, 0];
    let h0 = make_dg_padded(dg_contents[0]);

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    // Tampered SOD hash
    let mut bad_sod: [u8; 32] = [0xFF; 32];
    main(1, dg_contents, dg_lengths, expected, bad_sod);
}

// DI-9: Tampered DG content after hash computation - should fail
#[test(should_fail)]
fn test_tampered_dg_content_fails() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 72;
    dg_contents[0][1] = 101;
    dg_contents[0][2] = 108;
    dg_contents[0][3] = 108;
    dg_contents[0][4] = 111;

    // Compute hash of ORIGINAL content
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    // Tamper content AFTER hash was computed
    dg_contents[0][0] = 73; // H -> I

    main(1, dg_contents, [5, 0, 0, 0], expected, sod_hash);
}

// DI-10: dg_count = 0 - circuit asserts "Must have at least one data group"
#[test(should_fail)]
fn test_dg_count_zero_fails() {
    let dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    let dg_lengths: [u32; MAX_DG_COUNT] = [0, 0, 0, 0];
    let expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    let mut combined: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    let sod_hash: [u8; 32] = digest(combined);
    main(0, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-11: DG length exceeds MAX_DG_SIZE - circuit asserts "DG length exceeds maximum"
#[test(should_fail)]
fn test_dg_length_exceeds_max() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 65;

    // Length = 513, exceeds MAX_DG_SIZE = 512
    let dg_lengths: [u32; MAX_DG_COUNT] = [513, 0, 0, 0];

    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];
    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    main(1, dg_contents, dg_lengths, expected, sod_hash);
}

// DI-12: Realistic DG1 with ICAO TD3 MRZ data
#[test]
fn test_realistic_dg1_mrz_data() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    // TD3 MRZ: "P<UTODOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<L898902C36UTO9001014M2610154<<<<<<<<<<<<<<<8"
    // Line 1 (44 bytes):
    let line1: [u8; 44] = [
        80, 60, 85, 84, 79, 68, 79, 69, 60, 60, 74, 79, 72, 78, 60, 60, 60, 60, 60, 60, 60, 60, 60,
        60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    ];
    // Line 2 (44 bytes):
    let line2: [u8; 44] = [
        76, 56, 57, 56, 57, 48, 50, 67, 51, 54, 85, 84, 79, 57, 48, 48, 49, 48, 49, 52, 77, 50, 54,
        49, 48, 49, 53, 52, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 56,
    ];
    for i in 0..44 {
        dg_contents[0][i] = line1[i];
        dg_contents[0][44 + i] = line2[i];
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [88, 0, 0, 0];

    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    let sod_hash = compute_sod_hash(h0, zero, zero, zero);
    main(1, dg_contents, dg_lengths, expected, sod_hash);
}

// ============================================================
// E2E Cross-Circuit Integration Tests
// These verify hash chain consistency across the proof pipeline:
//   passport_verifier <- sod_hash -> data_integrity <- mrz_hash -> disclosure
// ============================================================

// E2E-1: sod_hash links passport_verifier and data_integrity
// The same sod_hash must work as private input to passport_verifier
// and as public input to data_integrity.
#[test]
fn test_passport_to_data_integrity_hash_link() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 80; // P
    dg_contents[0][1] = 65; // A
    dg_contents[0][2] = 83; // S
    dg_contents[0][3] = 83; // S

    let dg_lengths: [u32; MAX_DG_COUNT] = [4, 0, 0, 0];
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    // This sod_hash is the SAME value that passport_verifier verifies
    // via RSA signature, and that data_integrity uses as public input.
    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    // data_integrity passes with this sod_hash
    main(1, dg_contents, dg_lengths, expected, sod_hash);
    // passport_verifier would verify: RSA_verify(sod_hash, sig, modulus) == true
}

// E2E-2: DG1 contains MRZ -> sha256(mrz) = disclosure's mrz_hash
#[test]
fn test_data_integrity_to_disclosure_mrz_link() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];

    // DG1 = MRZ data (88 bytes TD3 format, padded to 512)
    let mut mrz: [u8; 88] = [60; 88];
    mrz[0] = 80;
    mrz[1] = 60;
    mrz[2] = 85;
    mrz[3] = 84;
    mrz[4] = 79; // P<UTO
    mrz[5] = 68;
    mrz[6] = 79;
    mrz[7] = 69; // DOE
    mrz[54] = 85;
    mrz[55] = 84;
    mrz[56] = 79; // nationality UTO
    mrz[57] = 48;
    mrz[58] = 48;
    mrz[59] = 48; // DOB 000315
    mrz[60] = 51;
    mrz[61] = 49;
    mrz[62] = 53;

    for i in 0..88 {
        dg_contents[0][i] = mrz[i];
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [88, 0, 0, 0];
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    // data_integrity verifies DG1 hash chain
    main(1, dg_contents, dg_lengths, expected, sod_hash);

    // For disclosure circuit, mrz_hash = sha256(mrz_data) where mrz_data = mrz[0..88]
    // The disclosure circuit would use this mrz_hash as public input.
    // Note: disclosure hashes the raw 88-byte MRZ, NOT the 512-byte padded DG1.
}

// E2E-3: Full pipeline hash consistency
// Canonical test vector for: SOD sig -> DG hash chain -> MRZ disclosure
#[test]
fn test_full_pipeline_hash_consistency() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];

    // MRZ data (88 bytes): P<UTODOE<<JOHN with nationality UTO, DOB 000315
    let mut mrz: [u8; 88] = [60; 88];
    mrz[0] = 80;
    mrz[1] = 60;
    mrz[2] = 85;
    mrz[3] = 84;
    mrz[4] = 79;
    mrz[5] = 68;
    mrz[6] = 79;
    mrz[7] = 69;
    mrz[8] = 60;
    mrz[9] = 60;
    mrz[10] = 74;
    mrz[11] = 79;
    mrz[12] = 72;
    mrz[13] = 78;
    mrz[54] = 85;
    mrz[55] = 84;
    mrz[56] = 79;
    mrz[57] = 48;
    mrz[58] = 48;
    mrz[59] = 48;
    mrz[60] = 51;
    mrz[61] = 49;
    mrz[62] = 53;

    // DG1 = MRZ padded to 512
    for i in 0..88 {
        dg_contents[0][i] = mrz[i];
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [88, 0, 0, 0];
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    // sod_hash: links passport_verifier <-> data_integrity
    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    // data_integrity verifies the chain
    main(1, dg_contents, dg_lengths, expected, sod_hash);

    // Pipeline summary:
    // 1. passport_verifier: RSA_verify(sod_hash, dsc_sig, dsc_modulus)
    // 2. data_integrity: verify DG hashes -> sod_hash (this test)
    // 3. disclosure: sha256(mrz_data) == mrz_hash, then selective disclosure
}

// E2E-4: Tampered DG1 content breaks the hash chain
#[test(should_fail)]
fn test_pipeline_tampered_dg1_breaks_chain() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];

    // Original MRZ
    let mut mrz: [u8; 88] = [60; 88];
    mrz[0] = 80;
    mrz[1] = 60;
    mrz[2] = 85;
    mrz[3] = 84;
    mrz[4] = 79;
    mrz[54] = 85;
    mrz[55] = 84;
    mrz[56] = 79;

    for i in 0..88 {
        dg_contents[0][i] = mrz[i];
    }

    // Hash of ORIGINAL content
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    // TAMPER: modify nationality in DG1 (UTO -> USA)
    dg_contents[0][56] = 65; // O -> A

    // data_integrity should FAIL: DG1 hash no longer matches expected
    main(1, dg_contents, [88, 0, 0, 0], expected, sod_hash);
}

// E2E-5: Wrong sod_hash breaks the chain
#[test(should_fail)]
fn test_pipeline_wrong_sod_breaks_chain() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    dg_contents[0][0] = 80;
    dg_contents[0][1] = 65;

    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];

    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    // Correct sod_hash
    let mut sod_hash = compute_sod_hash(h0, zero, zero, zero);
    // Tamper it
    sod_hash[0] ^= 0xFF;

    main(1, dg_contents, [2, 0, 0, 0], expected, sod_hash);
}

// ============================================================
// OpenAC extension: explicit DG1(MRZ) hash link for disclosure
// ============================================================

fn derive_td3_mrz_hash(dg1_content: [u8; MAX_DG_SIZE], dg1_length: u32) -> [u8; 32] {
    assert(dg1_length >= 88, "DG1 length too short for TD3 MRZ");

    let mut mrz_data: [u8; 88] = [0; 88];
    for i in 0..88 {
        mrz_data[i] = dg1_content[i];
    }

    digest(mrz_data)
}

fn main_with_mrz_link(
    dg_count: u8,
    dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT],
    dg_lengths: [u32; MAX_DG_COUNT],
    expected_dg_hashes: [[u8; 32]; MAX_DG_COUNT],
    sod_hash: [u8; 32],
    mrz_hash: [u8; 32],
) {
    main(
        dg_count,
        dg_contents,
        dg_lengths,
        expected_dg_hashes,
        sod_hash,
    );

    let computed_mrz_hash = derive_td3_mrz_hash(dg_contents[0], dg_lengths[0]);
    for i in 0..32 {
        assert(computed_mrz_hash[i] == mrz_hash[i], "MRZ hash link mismatch");
    }
}

#[test]
fn test_dg1_mrz_hash_output_matches_disclosure_input() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    let mut mrz: [u8; 88] = [60; 88];

    // TD3-style MRZ prefix
    mrz[0] = 80;
    mrz[1] = 60;
    mrz[2] = 85;
    mrz[3] = 84;
    mrz[4] = 79;
    mrz[5] = 68;
    mrz[6] = 79;
    mrz[7] = 69;
    mrz[8] = 60;
    mrz[9] = 60;
    mrz[10] = 74;
    mrz[11] = 79;
    mrz[12] = 72;
    mrz[13] = 78;
    mrz[54] = 85;
    mrz[55] = 84;
    mrz[56] = 79;
    mrz[57] = 48;
    mrz[58] = 48;
    mrz[59] = 48;
    mrz[60] = 51;
    mrz[61] = 49;
    mrz[62] = 53;

    for i in 0..88 {
        dg_contents[0][i] = mrz[i];
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [88, 0, 0, 0];
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];
    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;

    let sod_hash = compute_sod_hash(h0, zero, zero, zero);
    let mrz_hash = digest(mrz);

    main_with_mrz_link(1, dg_contents, dg_lengths, expected, sod_hash, mrz_hash);
}

#[test(should_fail)]
fn test_tampered_mrz_hash_link_fails() {
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    let mut mrz: [u8; 88] = [60; 88];

    mrz[0] = 80;
    mrz[1] = 60;
    mrz[2] = 85;
    mrz[3] = 84;
    mrz[4] = 79;
    mrz[54] = 85;
    mrz[55] = 84;
    mrz[56] = 79;
    mrz[57] = 48;
    mrz[58] = 48;
    mrz[59] = 48;
    mrz[60] = 51;
    mrz[61] = 49;
    mrz[62] = 53;

    for i in 0..88 {
        dg_contents[0][i] = mrz[i];
    }

    let dg_lengths: [u32; MAX_DG_COUNT] = [88, 0, 0, 0];
    let h0 = make_dg_padded(dg_contents[0]);
    let zero: [u8; 32] = [0; 32];
    let mut expected: [[u8; 32]; MAX_DG_COUNT] = [[0; 32]; MAX_DG_COUNT];
    expected[0] = h0;
    let sod_hash = compute_sod_hash(h0, zero, zero, zero);

    let mut bad_mrz_hash = digest(mrz);
    bad_mrz_hash[0] = bad_mrz_hash[0] ^ 0xFF;

    main_with_mrz_link(1, dg_contents, dg_lengths, expected, sod_hash, bad_mrz_hash);
}
