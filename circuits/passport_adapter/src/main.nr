use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::digest;

use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_PASSPORT};
use openac_core::device::pk_digest_from_bytes;
use openac_core::predicate::two_digit_year_to_four;
use openac_core::profile::pack_passport_profile;
use std::embedded_curve_ops::EmbeddedCurvePoint;

// OpenAC Passport Adapter (Prepare Phase, v3 -- Path A)
//
// Combines:
//   1. RSA-2048 signature verification (DSC -> SOD)  [from passport_verifier]
//   2. DG hash chain verification (SOD -> DG1)        [from data_integrity]
//   3. Pedersen commitment on Grumpkin with pk_digest [Path A device binding]
//
// Path A v3 change: the Pedersen commitment now binds a fifth element
// `pk_digest = pedersen_hash(enclave_pk coords)` so the matching Show circuit
// can enforce in-circuit ECDSA-P256 device binding. No ECDSA verify runs here
// (Prepare phase has no nonce yet -- that check lives in openac_show v3).
//
// Public outputs:
//   - modulus_limbs: RSA public key (issuer identity)
//   - out_commitment_x, out_commitment_y: Grumpkin Pedersen commitment point
//
// The commitment (C.x, C.y) is what links this prepare proof to the show proof.
// Verifier checks: prepare.out_commitment == show.out_commitment

global MAX_DG_COUNT: u32 = 4;
global MAX_DG_SIZE: u32 = 512;

/// Verify DG hash chain: each data group's content hashes to the expected hash,
/// and the combined hash of all DG hashes matches the SOD hash.
fn verify_dg_chain(
    sod_hash: [u8; 32],
    dg_count: u8,
    dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT],
    dg_lengths: [u32; MAX_DG_COUNT],
    expected_dg_hashes: [[u8; 32]; MAX_DG_COUNT],
) {
    assert(dg_count as u32 <= MAX_DG_COUNT, "Too many data groups");
    assert(dg_count > 0, "Must have at least one data group");

    let mut combined_preimage: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];

    for i in 0..MAX_DG_COUNT {
        if (i as u8) < dg_count {
            let mut dg_data: [u8; MAX_DG_SIZE] = [0; MAX_DG_SIZE];
            let len = dg_lengths[i];
            assert(len <= MAX_DG_SIZE as u32, "DG length exceeds maximum");

            for j in 0..MAX_DG_SIZE {
                if (j as u32) < len {
                    dg_data[j] = dg_contents[i][j];
                }
            }

            let computed_hash: [u8; 32] = digest(dg_data);

            for k in 0..32 {
                assert(computed_hash[k] == expected_dg_hashes[i][k], "Data group hash mismatch");
            }

            for k in 0..32 {
                combined_preimage[i * 32 + k] = computed_hash[k];
            }
        }
    }

    let computed_sod_hash: [u8; 32] = digest(combined_preimage);
    for i in 0..32 {
        assert(computed_sod_hash[i] == sod_hash[i], "SOD combined hash mismatch");
    }
}

fn extract_passport_profile(dg1_content: [u8; MAX_DG_SIZE]) -> (u32, u32, u32, [u8; 3]) {
    let nationality = [dg1_content[54], dg1_content[55], dg1_content[56]];
    let birth_yy: u32 = (dg1_content[57] - 48) as u32 * 10 + (dg1_content[58] - 48) as u32;
    let birth_mm: u32 = (dg1_content[59] - 48) as u32 * 10 + (dg1_content[60] - 48) as u32;
    let birth_dd: u32 = (dg1_content[61] - 48) as u32 * 10 + (dg1_content[62] - 48) as u32;
    let birth_year = two_digit_year_to_four(birth_yy, 50);
    (birth_year, birth_mm, birth_dd, nationality)
}

/// Compute the v3 Pedersen commitment for a passport credential using reopened profile
/// attributes plus the enclave pk digest.
/// The commitment binds to age/nationality inputs required by composite_show while retaining
/// a credential fingerprint from DG1 + SOD, and now also binds the device's enclave key.
fn compute_passport_commitment(
    sod_hash: [u8; 32],
    dg1_content: [u8; MAX_DG_SIZE],
    dg1_hash: [u8; 32],
    pk_digest: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    let (birth_year, birth_month, birth_day, nationality) = extract_passport_profile(dg1_content);
    let (attr_hi, attr_lo) = pack_passport_profile(
        sod_hash,
        dg1_hash,
        birth_year,
        birth_month,
        birth_day,
        nationality,
    );
    commit_attributes_v3(DOMAIN_PASSPORT, attr_hi, attr_lo, pk_digest, link_rand)
}

fn main(
    // === RSA signature verification inputs ===
    sod_hash: [u8; 32],
    signature_limbs: [u128; 18],
    modulus_limbs: pub [u128; 18],
    redc_limbs: [u128; 18],
    exponent: u32,
    // === DG hash chain inputs ===
    dg_count: u8,
    dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT],
    dg_lengths: [u32; MAX_DG_COUNT],
    expected_dg_hashes: [[u8; 32]; MAX_DG_COUNT],
    // === OpenAC commitment inputs ===
    link_rand: Field,
    // === Path A device-binding witnesses (enclave pk is private) ===
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // Step 1: Verify RSA-2048 signature (DSC -> SOD)
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, redc_limbs);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature_limbs };
    assert(
        verify_sha256_pkcs1v15(sod_hash, signature, exponent),
        "Passport DSC signature verification failed",
    );

    // Step 2: Verify DG hash chain (SOD -> DG1..DG4)
    verify_dg_chain(
        sod_hash,
        dg_count,
        dg_contents,
        dg_lengths,
        expected_dg_hashes,
    );

    // Step 3: Derive pk_digest from enclave pk (Path A v3, no ECDSA check in prepare).
    let pk_digest = pk_digest_from_bytes(enclave_pk_x, enclave_pk_y);

    // Step 4: Compute v3 Pedersen commitment on Grumpkin (binds pk_digest).
    let dg1_hash = expected_dg_hashes[0];
    let dg1_content = dg_contents[0];
    let commitment =
        compute_passport_commitment(sod_hash, dg1_content, dg1_hash, pk_digest, link_rand);
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);
}

// ============================================================
// Tests
// ============================================================

/// Generate deterministic test bytes from a seed
fn sample_bytes(seed: u8) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for i in 0..32 {
        out[i] = seed + (i as u8);
    }
    out
}

fn build_profile_dg1(nationality: [u8; 3], dob: [u8; 6], fill_seed: u8) -> [u8; MAX_DG_SIZE] {
    let mut data: [u8; MAX_DG_SIZE] = [fill_seed; MAX_DG_SIZE];
    data[54] = nationality[0];
    data[55] = nationality[1];
    data[56] = nationality[2];
    data[57] = dob[0];
    data[58] = dob[1];
    data[59] = dob[2];
    data[60] = dob[3];
    data[61] = dob[4];
    data[62] = dob[5];
    data
}

/// Build a single DG content array (zero-padded to MAX_DG_SIZE)
fn build_dg_content(seed: u8, length: u32) -> [u8; MAX_DG_SIZE] {
    let mut data: [u8; MAX_DG_SIZE] = [0; MAX_DG_SIZE];
    for i in 0..MAX_DG_SIZE {
        if (i as u32) < length {
            data[i] = seed + (i as u8);
        }
    }
    data
}

/// Build a valid single-DG test fixture.
/// Returns (sod_hash, dg_contents, dg_lengths, expected_dg_hashes) for 1 DG.
fn build_single_dg_fixture() -> ([u8; 32], [[u8; MAX_DG_SIZE]; MAX_DG_COUNT], [u32; MAX_DG_COUNT], [[u8; 32]; MAX_DG_COUNT]) {
    let dg1_data = build_dg_content(0x10, 64);
    let dg1_hash: [u8; 32] = digest(dg1_data);

    // SOD hash = SHA256(dg1_hash || zeros) for single DG
    let mut combined_preimage: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    for k in 0..32 {
        combined_preimage[k] = dg1_hash[k];
    }
    let sod_hash: [u8; 32] = digest(combined_preimage);

    let dg_contents = [dg1_data, [0; MAX_DG_SIZE], [0; MAX_DG_SIZE], [0; MAX_DG_SIZE]];
    let dg_lengths: [u32; MAX_DG_COUNT] = [64, 0, 0, 0];
    let expected_dg_hashes = [dg1_hash, [0; 32], [0; 32], [0; 32]];

    (sod_hash, dg_contents, dg_lengths, expected_dg_hashes)
}

/// Build a valid two-DG test fixture.
fn build_two_dg_fixture() -> ([u8; 32], [[u8; MAX_DG_SIZE]; MAX_DG_COUNT], [u32; MAX_DG_COUNT], [[u8; 32]; MAX_DG_COUNT]) {
    let dg1_data = build_dg_content(0x10, 64);
    let dg2_data = build_dg_content(0x20, 128);
    let dg1_hash: [u8; 32] = digest(dg1_data);
    let dg2_hash: [u8; 32] = digest(dg2_data);

    let mut combined_preimage: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    for k in 0..32 {
        combined_preimage[k] = dg1_hash[k];
        combined_preimage[32 + k] = dg2_hash[k];
    }
    let sod_hash: [u8; 32] = digest(combined_preimage);

    let dg_contents = [dg1_data, dg2_data, [0; MAX_DG_SIZE], [0; MAX_DG_SIZE]];
    let dg_lengths: [u32; MAX_DG_COUNT] = [64, 128, 0, 0];
    let expected_dg_hashes = [dg1_hash, dg2_hash, [0; 32], [0; 32]];

    (sod_hash, dg_contents, dg_lengths, expected_dg_hashes)
}

/// Canonical P-256 enclave test key (x) -- copied from
/// circuits/device_binding/src/main.nr so Path A tests here track the same fixture.
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

// --- DG hash chain tests ---

#[test]
fn test_dg_chain_single_dg_passes() {
    let (sod_hash, dg_contents, dg_lengths, expected_dg_hashes) = build_single_dg_fixture();
    verify_dg_chain(sod_hash, 1, dg_contents, dg_lengths, expected_dg_hashes);
}

#[test]
fn test_dg_chain_two_dgs_passes() {
    let (sod_hash, dg_contents, dg_lengths, expected_dg_hashes) = build_two_dg_fixture();
    verify_dg_chain(sod_hash, 2, dg_contents, dg_lengths, expected_dg_hashes);
}

#[test(should_fail)]
fn test_dg_chain_fails_on_wrong_dg_hash() {
    let (sod_hash, dg_contents, dg_lengths, mut expected_dg_hashes) = build_single_dg_fixture();
    expected_dg_hashes[0][0] ^= 0xFF;
    verify_dg_chain(sod_hash, 1, dg_contents, dg_lengths, expected_dg_hashes);
}

#[test(should_fail)]
fn test_dg_chain_fails_on_wrong_sod_hash() {
    let (mut sod_hash, dg_contents, dg_lengths, expected_dg_hashes) = build_single_dg_fixture();
    sod_hash[0] ^= 0xFF;
    verify_dg_chain(sod_hash, 1, dg_contents, dg_lengths, expected_dg_hashes);
}

// --- Pedersen commitment tests ---

#[test]
fn test_commitment_deterministic() {
    let sod_hash = sample_bytes(0x10);
    let dg1 = build_profile_dg1([84, 87, 78], [48, 48, 48, 51, 49, 53], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, 42);
    let c2 = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, 42);
    assert(c1.x == c2.x, "Commitment X should be deterministic");
    assert(c1.y == c2.y, "Commitment Y should be deterministic");
}

#[test]
fn test_commitment_changes_with_link_rand() {
    let sod_hash = sample_bytes(0x10);
    let dg1 = build_profile_dg1([84, 87, 78], [48, 48, 48, 51, 49, 53], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, 42);
    let c2 = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, 43);
    assert(c1.x != c2.x, "Different link_rand must produce different commitment");
}

#[test]
fn test_commitment_changes_with_sod_hash() {
    let dg1 = build_profile_dg1([84, 87, 78], [48, 48, 48, 51, 49, 53], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_passport_commitment(sample_bytes(0x10), dg1, dg1_hash, pk_digest, 42);
    let c2 = compute_passport_commitment(sample_bytes(0x11), dg1, dg1_hash, pk_digest, 42);
    assert(c1.x != c2.x, "Different sod_hash must produce different commitment");
}

#[test]
fn test_commitment_changes_with_enclave_pk() {
    // Path A property: swapping enclave pk bytes must change the v3 commitment,
    // locking ownership of the credential to a single device key.
    let sod_hash = sample_bytes(0x10);
    let dg1 = build_profile_dg1([84, 87, 78], [48, 48, 48, 51, 49, 53], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let pk_digest_a = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let mut pk_x_b = test_enclave_pk_x();
    pk_x_b[0] ^= 0x01;
    let pk_digest_b = pk_digest_from_bytes(pk_x_b, test_enclave_pk_y());
    let c1 = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest_a, 42);
    let c2 = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest_b, 42);
    assert(c1.x != c2.x, "Different enclave pk must produce different commitment");
}

#[test]
fn test_commitment_matches_manual_recomputation() {
    let sod_hash = sample_bytes(0x10);
    let dg1 = build_profile_dg1([84, 87, 78], [48, 48, 48, 51, 49, 53], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let rand: Field = 77;
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, rand);

    let (attr_hi, attr_lo) = pack_passport_profile(sod_hash, dg1_hash, 2000, 3, 15, [84, 87, 78]);
    let c_manual = commit_attributes_v3(DOMAIN_PASSPORT, attr_hi, attr_lo, pk_digest, rand);

    assert(c.x == c_manual.x, "Commitment X must match manual recomputation");
    assert(c.y == c_manual.y, "Commitment Y must match manual recomputation");
}

#[test]
fn test_commitment_with_dg_chain_integration() {
    let dg1 = build_profile_dg1([85, 83, 65], [57, 48, 48, 49, 48, 49], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let mut combined_preimage: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    for i in 0..32 {
        combined_preimage[i] = dg1_hash[i];
    }
    let sod_hash: [u8; 32] = digest(combined_preimage);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, 99);
    assert(c.x != 0, "Commitment X should be non-zero for valid inputs");
    assert(c.y != 0, "Commitment Y should be non-zero for valid inputs");
}
