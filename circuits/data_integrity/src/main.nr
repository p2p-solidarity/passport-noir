use sha256::digest;

// Data Integrity Verifier (DG Hash Chain)
//
// Verifies that passport data groups (DG1, DG2, etc.) hash correctly
// into the Security Object Document (SOD). This ensures the passport
// data has not been tampered with.
//
// ICAO 9303 specifies that each data group is individually hashed,
// and the collection of hashes is stored in the SOD's LDS Security Object.

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
                assert(
                    computed_hash[k] == expected_dg_hashes[i][k],
                    "Data group hash mismatch",
                );
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
        assert(
            computed_sod_hash[i] == sod_hash[i],
            "SOD combined hash mismatch",
        );
    }
}

#[test]
fn test_single_dg() {
    // Test with a single data group
    let mut dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT] = [[0; MAX_DG_SIZE]; MAX_DG_COUNT];
    // Simple test data: "Hello"
    dg_contents[0][0] = 72;  // H
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
