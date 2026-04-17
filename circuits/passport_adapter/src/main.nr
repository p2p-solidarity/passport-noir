use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::digest;

use openac_core::commit::{
    assert_commitment_eq, commit_attributes_v3, DOMAIN_CSCA_NODE, DOMAIN_PASSPORT,
};
use openac_core::device::pk_digest_from_bytes;
use openac_core::merkle::{compute_csca_leaf, CSCA_MERKLE_DEPTH, verify_inclusion_depth_8};
use openac_core::predicate::two_digit_year_to_four;
use openac_core::profile::pack_passport_profile;
use openac_core::smt::{SMT_DEPTH, smt_fold, verify_non_membership};
use std::embedded_curve_ops::EmbeddedCurvePoint;
use std::hash::pedersen_hash;

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

// DSC certificate TBS envelope size. Matches jwt_x5c_adapter's CERT_TBS_LEN so
// off-circuit tooling that generates RSA test vectors can be shared between the
// passport and x509 prepare flows.
global DSC_TBS_LEN: u32 = 1536;
global RSA_LIMB_COUNT: u32 = 18;
global RSA_LIMB_BYTES: u32 = 16;
global DSC_MODULUS_BYTES: u32 = RSA_LIMB_COUNT * RSA_LIMB_BYTES;
// CSCA -> DSC RSA signature uses RSA-2048 PKCS#1v1.5 with exponent 65537, per
// ICAO 9303 conformance (same parameters as the DSC -> SOD signature).
global CSCA_RSA_EXPONENT: u32 = 65537;

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

/// Big-endian-pack 16 bytes of a DSC TBS buffer into a `u128`. Used when
/// extracting the 18 RSA-2048 modulus limbs from the TBS envelope.
fn bytes16_to_u128_at(data: [u8; DSC_TBS_LEN], start: u32) -> u128 {
    let mut out: u128 = 0;
    for i in 0..RSA_LIMB_BYTES {
        out = out * 256 + data[start + i] as u128;
    }
    out
}

/// Extract the DSC RSA-2048 modulus from the TBS envelope, assuming the modulus
/// bytes live at offset 0. This matches the canonical TBS layout shared with
/// `jwt_x5c_adapter`. The app layer normalises the real ICAO TBS into this form
/// before passing the bytes into the circuit (see spec/x509-contract.md sec. 5.3).
fn extract_dsc_modulus_limbs(dsc_tbs: [u8; DSC_TBS_LEN]) -> [u128; RSA_LIMB_COUNT] {
    let mut limbs: [u128; RSA_LIMB_COUNT] = [0; RSA_LIMB_COUNT];
    for limb_idx in 0..RSA_LIMB_COUNT {
        limbs[limb_idx] = bytes16_to_u128_at(dsc_tbs, limb_idx * RSA_LIMB_BYTES);
    }
    limbs
}

/// Verify the CSCA -> DSC issuance chain.
///
///   1. SHA256 the DSC TBS envelope.
///   2. Verify the CSCA RSA-2048 signature over that hash under CSCA modulus.
///   3. Re-extract the DSC modulus from the TBS and assert it matches the one
///      used to verify DSC -> SOD. This is how an attacker is prevented from
///      swapping in a DSC public key that the CSCA never signed.
///   4. Hash the CSCA modulus into a leaf and verify depth-8 Merkle inclusion
///      under the ICAO Master List root.
fn verify_csca_chain(
    csca_modulus_limbs: [u128; RSA_LIMB_COUNT],
    csca_redc_limbs: [u128; RSA_LIMB_COUNT],
    dsc_tbs: [u8; DSC_TBS_LEN],
    dsc_cert_sig_limbs: [u128; RSA_LIMB_COUNT],
    dsc_modulus_limbs: [u128; RSA_LIMB_COUNT],
    csca_merkle_index: u32,
    csca_merkle_siblings: [Field; CSCA_MERKLE_DEPTH],
    csca_root: Field,
) {
    // 1 + 2: CSCA signs DSC TBS.
    let dsc_tbs_hash: [u8; 32] = digest(dsc_tbs);
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(false, csca_modulus_limbs, csca_redc_limbs);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: dsc_cert_sig_limbs };
    assert(
        verify_sha256_pkcs1v15(dsc_tbs_hash, signature, CSCA_RSA_EXPONENT),
        "CSCA signature over DSC TBS failed verification",
    );

    // 3. DSC modulus extracted from the TBS must match the one used for SOD.
    let extracted = extract_dsc_modulus_limbs(dsc_tbs);
    for i in 0..RSA_LIMB_COUNT {
        assert(extracted[i] == dsc_modulus_limbs[i], "DSC modulus mismatch with CSCA-signed TBS");
    }

    // 4. CSCA must appear in the Master List (ICAO snapshot).
    let csca_leaf = compute_csca_leaf(csca_modulus_limbs);
    verify_inclusion_depth_8(
        csca_leaf,
        csca_merkle_index,
        csca_merkle_siblings,
        csca_root,
    );
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
    // === RSA DSC -> SOD inputs ===
    sod_hash: [u8; 32],
    signature_limbs: [u128; RSA_LIMB_COUNT],
    modulus_limbs: [u128; RSA_LIMB_COUNT],
    redc_limbs: [u128; RSA_LIMB_COUNT],
    exponent: u32,
    // === CSCA -> DSC chain inputs (v3.1) ===
    csca_modulus_limbs: [u128; RSA_LIMB_COUNT],
    csca_redc_limbs: [u128; RSA_LIMB_COUNT],
    dsc_tbs: [u8; DSC_TBS_LEN],
    dsc_cert_sig_limbs: [u128; RSA_LIMB_COUNT],
    csca_merkle_index: u32,
    csca_merkle_siblings: [Field; CSCA_MERKLE_DEPTH],
    // === DSC revocation SMT inputs (v3.1) ===
    dsc_serial: [u8; 20],
    smt_siblings: [Field; SMT_DEPTH],
    smt_old_key: Field,
    smt_old_value: Field,
    smt_is_old0: bool,
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
    // === Public trust anchors (v3.1) ===
    csca_root: pub Field,
    dsc_smt_root: pub Field,
    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // Step 1: Verify RSA-2048 signature (DSC -> SOD).
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, redc_limbs);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature_limbs };
    assert(
        verify_sha256_pkcs1v15(sod_hash, signature, exponent),
        "Passport DSC signature verification failed",
    );

    // Step 2 (v3.1): Verify CSCA -> DSC issuance chain + Master List inclusion.
    verify_csca_chain(
        csca_modulus_limbs,
        csca_redc_limbs,
        dsc_tbs,
        dsc_cert_sig_limbs,
        modulus_limbs,
        csca_merkle_index,
        csca_merkle_siblings,
        csca_root,
    );

    // Step 3 (v3.1): DSC serial must NOT appear in the revocation SMT.
    verify_non_membership(
        dsc_serial,
        smt_siblings,
        smt_old_key,
        smt_old_value,
        smt_is_old0,
        dsc_smt_root,
    );

    // Step 4: Verify DG hash chain (SOD -> DG1..DG4).
    verify_dg_chain(
        sod_hash,
        dg_count,
        dg_contents,
        dg_lengths,
        expected_dg_hashes,
    );

    // Step 5: Derive pk_digest from enclave pk (Path A v3, no ECDSA check in prepare).
    let pk_digest = pk_digest_from_bytes(enclave_pk_x, enclave_pk_y);

    // Step 6: Compute v3 Pedersen commitment on Grumpkin (binds pk_digest).
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

// ============================================================
// CSCA chain + revocation SMT fixtures (v3.1)
// ============================================================
//
// Reuse the jwt_x5c_adapter RSA chain by role-swap: the issuer cert there
// becomes a passport CSCA, and the leaf cert becomes a passport DSC. This
// lets us exercise `verify_csca_chain` against genuine RSA-2048 signatures
// without generating a second Python test-vector pipeline. The numeric
// limb values are copied verbatim from circuits/jwt_x5c_adapter/src/main.nr
// and must stay in sync if that fixture is ever regenerated.

fn csca_modulus_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0xa16bbf6582c968237950f84ced9edb,
        0x818a4b367195bfba98916c74db2b8c,
        0x2312046fd1de3c28ae6a48436db0f1,
        0xbdc9f18ecd47ae62a8d8823e01a295,
        0x716e09f175f001601a561d2efdc2ed,
        0x5027385467708162ac83d2960cb8b3,
        0x64a45f4b496498bbdc26185000194b,
        0x509996a279619ee5ac3b15355f6886,
        0xcdbffe389ee031cd3a97fe58225b98,
        0xb9f8b994f525236b8f09177653a37e,
        0x88f0a4da4667cd857a36cd8cc47461,
        0x6baf3ccec91b662de86c678f92441b,
        0x13aae58bdeef623427011e69414d1e,
        0xa897b27655f97d48245eac2d1defd7,
        0x504a4d58dc77a1933ebf387eaef139,
        0x1112bdb40b60505df63d230801126d,
        0x817aad06370dabb3887f97cd96f0f5,
        0xbd,
    ]
}

fn csca_redc_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0xed9ca6c20e41f3f9885895ca784496,
        0x4181c99a3064c64474949d6f591715,
        0x88803734a8be4e8180a3d95ada54e0,
        0xc26dc22c0bfddafefa514f4ba30112,
        0xc63959360d24e3989b4ae312ddb28f,
        0xba7a656e61c4822cf4f90670f9635a,
        0x713396d9ce877cbe28fc3d465b149c,
        0x93c198226fe67e8ddd89565ceb470f,
        0xd95d3613ad0407e74a340b520851f9,
        0x5290b6f990369bcc6a599fb3e00e51,
        0xfc71f48d520e54a70be8369de367d1,
        0xc415244e22f6db48824c02cac34369,
        0xd766dbe929628e5adad607541110c5,
        0x7c53b15f95439be4566c91f8f1c841,
        0x9ff1195239138f9d5553fb358b027f,
        0xd1171db05c9a2f40589823492e00be,
        0xd36c02d1b91a592989f8487ed66dc4,
        0x159,
    ]
}

fn dsc_modulus_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0x6a0f89c4287e611ddcb155299044f9,
        0x7b0fec848b24c645a648632b0de148,
        0xe12d980728f2858a2688b963989a56,
        0x2f53114d520a9581d70f1fadf9048e,
        0x2f3a56673bafff8cb841a7beecb818,
        0xf2a3eefdc4be88717442a5fc3b7780,
        0x4c45c64fe7e76cf7dda3c73d47bf39,
        0x5417a4f6dcff8502b85c5cde1f581b,
        0xc61fa143320d12cc9a79360207c492,
        0xd5ffe9b78c4bc1cdc23db4235cf1f9,
        0x355f20e947641002d4b1260941fcd1,
        0xfc276bb43e4975ab8a8a7681f0a228,
        0xb43a6592fc8c4f5aec0d321e1be6a7,
        0x9e50c8ac30df61e09e037dda471dbf,
        0x97afef97f4ec3fe0038e9ffa9129f6,
        0x470895ba964416edb0eb8eefd5c582,
        0x4b114619d380a52f20ccf0c8a28bbc,
        0x9f,
    ]
}

fn dsc_cert_sig_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0x6ca221e94f6ff9b3d863c9dde869b5,
        0x2ff7ac22522702b8a9f7bf5317e1ab,
        0x750c9da91d8b36e3ac438e0fce92a8,
        0xea1604f67de54f8934b261d90e44b9,
        0xce01c8cc4edbb6feee906529a3a6e7,
        0x355cbd684f2f9d24518ce498113ad4,
        0xbf98bcee25a4afa2b325aeb676e4bc,
        0x87230cda8992617cc0aad28b938539,
        0x52b4e2618b18cc5708b03065aa1b11,
        0x225addad17aadc2cd8ae1fc88ebec9,
        0x141c6bc2667fa21ffae8ce1a206fdb,
        0xca4dd92f0d7ffc3b47ee9ab2f37fb8,
        0x87c5b955a596aaff969485c6003ac,
        0x808b50ecc5eb2a03ba3beb6a8ea1d,
        0xeecec0985e51c63ce26a4b464b0219,
        0xa0ad1dba4c184e73f7dbfc7713a7d8,
        0x73d6c179a3503a437fda9e90b89629,
        0x4,
    ]
}

fn dsc_modulus_bytes() -> [u8; DSC_MODULUS_BYTES] {
    [
        0, 106, 15, 137, 196, 40, 126, 97, 29, 220, 177, 85, 41, 144, 68, 249, 0, 123, 15, 236, 132,
        139, 36, 198, 69, 166, 72, 99, 43, 13, 225, 72, 0, 225, 45, 152, 7, 40, 242, 133, 138, 38,
        136, 185, 99, 152, 154, 86, 0, 47, 83, 17, 77, 82, 10, 149, 129, 215, 15, 31, 173, 249, 4,
        142, 0, 47, 58, 86, 103, 59, 175, 255, 140, 184, 65, 167, 190, 236, 184, 24, 0, 242, 163,
        238, 253, 196, 190, 136, 113, 116, 66, 165, 252, 59, 119, 128, 0, 76, 69, 198, 79, 231, 231,
        108, 247, 221, 163, 199, 61, 71, 191, 57, 0, 84, 23, 164, 246, 220, 255, 133, 2, 184, 92,
        92, 222, 31, 88, 27, 0, 198, 31, 161, 67, 50, 13, 18, 204, 154, 121, 54, 2, 7, 196, 146, 0,
        213, 255, 233, 183, 140, 75, 193, 205, 194, 61, 180, 35, 92, 241, 249, 0, 53, 95, 32, 233,
        71, 100, 16, 2, 212, 177, 38, 9, 65, 252, 209, 0, 252, 39, 107, 180, 62, 73, 117, 171, 138,
        138, 118, 129, 240, 162, 40, 0, 180, 58, 101, 146, 252, 140, 79, 90, 236, 13, 50, 30, 27,
        230, 167, 0, 158, 80, 200, 172, 48, 223, 97, 224, 158, 3, 125, 218, 71, 29, 191, 0, 151,
        175, 239, 151, 244, 236, 63, 224, 3, 142, 159, 250, 145, 41, 246, 0, 71, 8, 149, 186, 150,
        68, 22, 237, 176, 235, 142, 239, 213, 197, 130, 0, 75, 17, 70, 25, 211, 128, 165, 47, 32,
        204, 240, 200, 162, 139, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 159,
    ]
}

fn build_dsc_tbs() -> [u8; DSC_TBS_LEN] {
    let modulus_bytes = dsc_modulus_bytes();
    // Canonical TBS layout: 288 bytes of modulus then a marker tail for integrity.
    let meta: [u8; 32] = [
        108, 101, 97, 102, 45, 99, 101, 114, 116, 58, 58, 115, 111, 108, 105, 100, 97, 114, 105,
        116, 121, 58, 58, 120, 53, 48, 57, 58, 58, 50, 48, 50,
    ];
    let mut out: [u8; DSC_TBS_LEN] = [0; DSC_TBS_LEN];
    for i in 0..DSC_MODULUS_BYTES {
        out[i] = modulus_bytes[i];
    }
    for i in 0..32 {
        out[DSC_MODULUS_BYTES + i] = meta[i];
    }
    out[DSC_MODULUS_BYTES + 32] = 54;
    out
}

fn dsc_serial() -> [u8; 20] {
    [1, 35, 69, 103, 137, 171, 205, 239, 254, 220, 186, 152, 118, 84, 50, 16, 202, 254, 186, 190]
}

fn dsc_smt_siblings() -> [Field; SMT_DEPTH] {
    let mut siblings: [Field; SMT_DEPTH] = [0; SMT_DEPTH];
    for i in 0..SMT_DEPTH {
        siblings[i] = 123456 + i as Field;
    }
    siblings
}

fn dsc_smt_root_computed() -> Field {
    // Mirrors openac_core::smt::verify_non_membership with smt_is_old0 = true.
    let siblings = dsc_smt_siblings();
    let serial = dsc_serial();
    let mut node: Field = 0;
    for depth in 0..SMT_DEPTH {
        let byte = serial[depth / 8];
        let shift: u8 = 7 - ((depth % 8) as u8);
        let go_right = ((byte >> shift) & 1) == 1;
        node = smt_fold(node, siblings[depth], go_right);
    }
    node
}

fn csca_merkle_siblings() -> [Field; CSCA_MERKLE_DEPTH] {
    let mut siblings: [Field; CSCA_MERKLE_DEPTH] = [0; CSCA_MERKLE_DEPTH];
    for i in 0..CSCA_MERKLE_DEPTH {
        siblings[i] = 555_000 + i as Field;
    }
    siblings
}

fn csca_root_computed() -> Field {
    // CSCA appears at index 0 under the test Master List snapshot.
    let leaf = compute_csca_leaf(csca_modulus_limbs());
    let siblings = csca_merkle_siblings();
    let mut node = leaf;
    for depth in 0..CSCA_MERKLE_DEPTH {
        // go_right = false for all bits of index 0.
        node = pedersen_hash([DOMAIN_CSCA_NODE, node, siblings[depth]]);
    }
    node
}

// --- CSCA chain tests ---
//
// NOTE: `verify_csca_chain` is exercised end-to-end only through negative
// fixtures here. Generating a fully valid ICAO-style RSA-2048 fixture
// (signing real DSC TBS bytes under the CSCA modulus) requires external
// tooling (Python `cryptography` or openssl); those vectors will be added
// in a follow-up PR once the CSCA Master List snapshot builder lands
// (tracked in spec/x509-contract.md sec. 5.3 / spec/x509-migration.md Phase 4).
// The Merkle and SMT subproofs have dedicated happy-path coverage in
// `openac_core::merkle` and `openac_core::smt`; the DSC modulus extractor
// is covered below.

#[test]
fn test_extract_dsc_modulus_roundtrip() {
    let extracted = extract_dsc_modulus_limbs(build_dsc_tbs());
    let expected = dsc_modulus_limbs();
    for i in 0..RSA_LIMB_COUNT {
        assert(extracted[i] == expected[i], "DSC modulus extraction should round-trip");
    }
}

#[test(should_fail)]
fn test_csca_chain_fails_on_tampered_dsc_tbs() {
    let mut tampered = build_dsc_tbs();
    tampered[DSC_MODULUS_BYTES + 5] ^= 0xFF;
    verify_csca_chain(
        csca_modulus_limbs(),
        csca_redc_limbs(),
        tampered,
        dsc_cert_sig_limbs(),
        dsc_modulus_limbs(),
        0,
        csca_merkle_siblings(),
        csca_root_computed(),
    );
}

#[test(should_fail)]
fn test_csca_chain_fails_on_wrong_csca_root() {
    let mut bad_root = csca_root_computed();
    bad_root += 1;
    verify_csca_chain(
        csca_modulus_limbs(),
        csca_redc_limbs(),
        build_dsc_tbs(),
        dsc_cert_sig_limbs(),
        dsc_modulus_limbs(),
        0,
        csca_merkle_siblings(),
        bad_root,
    );
}

#[test(should_fail)]
fn test_csca_chain_fails_on_dsc_modulus_mismatch() {
    let mut tampered_dsc_modulus = dsc_modulus_limbs();
    tampered_dsc_modulus[0] ^= 1;
    verify_csca_chain(
        csca_modulus_limbs(),
        csca_redc_limbs(),
        build_dsc_tbs(),
        dsc_cert_sig_limbs(),
        tampered_dsc_modulus,
        0,
        csca_merkle_siblings(),
        csca_root_computed(),
    );
}

// --- DSC revocation SMT tests (thin wrappers, primitive already tested in openac_core) ---

#[test]
fn test_dsc_non_membership_passes_for_unrevoked_serial() {
    verify_non_membership(
        dsc_serial(),
        dsc_smt_siblings(),
        0,
        0,
        true,
        dsc_smt_root_computed(),
    );
}

#[test(should_fail)]
fn test_dsc_non_membership_fails_on_wrong_root() {
    let mut bad_root = dsc_smt_root_computed();
    bad_root += 1;
    verify_non_membership(dsc_serial(), dsc_smt_siblings(), 0, 0, true, bad_root);
}
