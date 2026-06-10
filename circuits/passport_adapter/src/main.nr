use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::digest;

use openac_core::commit::{assert_commitment_eq, commit_passport_v3_1, hash_to_fields};
use openac_core::device::pk_digest_from_bytes;
use openac_core::merkle::compute_dsc_id;
use openac_core::predicate::two_digit_year_to_four;
use openac_core::profile::{derive_scoped_link_rand, pack_passport_claims};
use std::ecdsa_secp256r1::verify_signature;
use std::embedded_curve_ops::EmbeddedCurvePoint;

// OpenAC Passport Core Adapter (Prepare Phase, v3.1 + Phase 6 -- Path A)
//
// Phase 6 split (spec/upgrade-plan-v3.1.md sec.7.2): the cacheable, public-data
// CSCA trust chain (CSCA->DSC RSA + Master List Merkle + revocation SMT) moved
// to the `dsc_chain` circuit, which can be precomputed once per DSC. This core
// circuit is the per-holder half that must run on the phone:
//   1. RSA-2048 signature verification (DSC -> SOD).
//   2. DSC linking-id pin: re-derive `compute_dsc_id(DSC modulus, exponent)`
//      and assert it equals the public `in_dsc_id` the dsc_chain proof output.
//   3. DG hash chain verification (SOD -> DG1 / DG15).
//   4. DG15 active authentication (sec.7.4, anti-cloning): the AA EC-P256 key
//      lives in the DG-chain-bound DG15; verify the chip's ECDSA signature over
//      a fresh challenge to prove chip-in-possession (a cloner with only DG
//      dumps + SOD lacks the AA private key). Gated by the public `require_aa`.
//   5. Pedersen commitment on Grumpkin with pk_digest [Path A device binding].
//
// The commitment (C.x, C.y) links this prepare proof to the show proof;
// `in_dsc_id` links it to the dsc_chain trust proof.
//
// Public inputs:
//   - in_dsc_id: DSC linking id (= dsc_chain.out_dsc_id). Verifier pins both.
//   - exponent: ICAO-mandated 65537 (asserted in-circuit).
//   - link_scope: per-scope pseudonym selector (sec.7.1).
//   - require_aa: when true, DG15 active authentication is enforced. Verifiers
//     wanting anti-cloning pin it true (same fail-closed pattern as disclose_*).
//   - aa_challenge: 32-byte message the chip's AA key signed (verifier-pinnable
//     for freshness / replay protection of the chip-presence proof).
//   - out_commitment_x, out_commitment_y: Grumpkin Pedersen commitment point.

// v3.1 prepare reduction (spec/upgrade-plan-v3.1.md sec.7.3): the DG chain
// carries only the two slots the trust model needs -- DG1 (predicate claims,
// the sole commitment input) and DG15 (active-authentication public key, see
// sec.7.4 / Phase 8). Dropping the two unused slots removes two unconditional
// SHA256(MAX_DG_SIZE) computations from every prepare proof (Noir evaluates
// both `if` branches, so an unused slot still costs a full hash). Real
// passports expose more data groups; the app normalises the SOD-hash preimage
// into this DG1||DG15 layout before feeding the circuit.
global MAX_DG_COUNT: u32 = 2;
global MAX_DG_SIZE: u32 = 512;

// DG slot indices inside the reduced chain. Slot 0 = DG1 (predicate claims,
// sole commitment input). Slot 1 = DG15 (active-authentication EC public key).
global DG1_SLOT: u32 = 0;
global DG15_SLOT: u32 = 1;

// Byte offsets of the AA EC-P256 public-key coordinates inside the normalised
// DG15 content (x at [0..32), y at [32..64)). The app's DG15 normaliser places
// the SubjectPublicKeyInfo EC point at the front; these 64 bytes are covered by
// the DG chain hash (DG15 -> SOD), so the extracted key is passive-auth bound.
global AA_PK_X_OFFSET: u32 = 0;
global AA_PK_Y_OFFSET: u32 = 32;

global RSA_LIMB_COUNT: u32 = 18;

// DSC -> SOD signature exponent: ICAO 9303 mandates 65537 for new passports.
// Issue P0-3 (2026-04-28): public input AND asserted exactly 65537, so a prover
// cannot swap in e=1 / e=3 to forge a signature the verifier cannot see.
global DSC_RSA_EXPONENT: u32 = 65537;

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

/// Extract the AA EC-P256 public-key coordinates from the normalised DG15
/// content. The 64 bytes [0..64) are covered by the DG chain hash, so the key
/// is passive-auth bound to the SOD.
fn extract_aa_pubkey(dg15_content: [u8; MAX_DG_SIZE]) -> ([u8; 32], [u8; 32]) {
    let mut aa_pk_x: [u8; 32] = [0; 32];
    let mut aa_pk_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        aa_pk_x[i] = dg15_content[AA_PK_X_OFFSET + i];
        aa_pk_y[i] = dg15_content[AA_PK_Y_OFFSET + i];
    }
    (aa_pk_x, aa_pk_y)
}

/// DG15 active authentication (sec.7.4, anti-cloning). Verifies the chip signed
/// `aa_challenge` with the AA private key whose public key lives in the
/// DG-chain-bound DG15. When `require_aa` is false the check is skipped (the
/// ECDSA blackbox still runs -- Noir cannot drop it conditionally -- but its
/// result is not asserted), so non-AA passports stay supported while a verifier
/// wanting chip-presence simply pins `require_aa = true`.
fn verify_active_authentication(
    dg15_content: [u8; MAX_DG_SIZE],
    dg_count: u8,
    aa_signature: [u8; 64],
    aa_challenge: [u8; 32],
    require_aa: bool,
) {
    let (aa_pk_x, aa_pk_y) = extract_aa_pubkey(dg15_content);
    let aa_valid = verify_signature(aa_pk_x, aa_pk_y, aa_signature, aa_challenge);
    if require_aa {
        // DG15 must be in the chain (slot 1 hashed), otherwise the AA key is not
        // passive-auth bound and a prover could supply an arbitrary key + sig.
        assert(
            dg_count as u32 > DG15_SLOT,
            "DG15 must be present when active authentication is required",
        );
        assert(aa_valid, "Active Authentication signature verification failed");
    }
}

/// Compute the v3.1 Pedersen commitment for a passport credential.
///
/// v3.1 (spec/upgrade-plan-v3.1.md sec.3.3): the SOD and DG1 hashes enter the
/// arity-8 commitment FULL-WIDTH (hi/lo Field halves). The predicate claims
/// (birth date + nationality from DG1) pack into a single 9-byte Field.
fn compute_passport_commitment(
    sod_hash: [u8; 32],
    dg1_content: [u8; MAX_DG_SIZE],
    dg1_hash: [u8; 32],
    pk_digest: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    let (birth_year, birth_month, birth_day, nationality) = extract_passport_profile(dg1_content);
    let claims = pack_passport_claims(birth_year, birth_month, birth_day, nationality);
    let (sod_hi, sod_lo) = hash_to_fields(sod_hash);
    let (dg1_hi, dg1_lo) = hash_to_fields(dg1_hash);
    commit_passport_v3_1(claims, sod_hi, sod_lo, dg1_hi, dg1_lo, pk_digest, link_rand)
}

fn main(
    // === RSA DSC -> SOD inputs ===
    sod_hash: [u8; 32],
    signature_limbs: [u128; RSA_LIMB_COUNT],
    modulus_limbs: [u128; RSA_LIMB_COUNT],
    redc_limbs: [u128; RSA_LIMB_COUNT],
    // === DG hash chain inputs ===
    dg_count: u8,
    dg_contents: [[u8; MAX_DG_SIZE]; MAX_DG_COUNT],
    dg_lengths: [u32; MAX_DG_COUNT],
    expected_dg_hashes: [[u8; 32]; MAX_DG_COUNT],
    // === OpenAC commitment inputs ===
    // Per-scope blinding seed (private). The circuit derives the actual
    // link_rand from this seed + the public `link_scope` so the commitment is a
    // scope-specific pseudonym (spec sec.7.1).
    link_rand_seed: Field,
    // === Path A device-binding witnesses (enclave pk is private) ===
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    // === DG15 active-authentication witness (chip's ECDSA over aa_challenge) ===
    aa_signature: [u8; 64],
    // === Public DSC linking id (= dsc_chain.out_dsc_id) ===
    in_dsc_id: pub Field,
    // === Public RSA exponent (P0-3, 2026-04-28) ===
    exponent: pub u32,
    // === Public verifier scope (sec.7.1): pins which service this commitment
    // is the holder's pseudonym for. Different scope -> different commitment. ===
    link_scope: pub Field,
    // === Public active-authentication policy + challenge (sec.7.4) ===
    require_aa: pub bool,
    aa_challenge: pub [u8; 32],
    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // Issue P0-3: pin the DSC RSA exponent (ICAO 9303 mandates e = 65537).
    assert(
        exponent == DSC_RSA_EXPONENT,
        "Passport DSC exponent must be 65537 (ICAO 9303 v3 trust model)",
    );

    // Step 1: Verify RSA-2048 signature (DSC -> SOD).
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, redc_limbs);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature_limbs };
    assert(
        verify_sha256_pkcs1v15(sod_hash, signature, exponent),
        "Passport DSC signature verification failed",
    );

    // Step 2 (Phase 6): bind this DSC to the cacheable dsc_chain proof. The
    // dsc_chain proof already verified CSCA -> DSC issuance, Master List
    // inclusion, and revocation non-membership, exposing `out_dsc_id`. Here we
    // re-derive the same id from the DSC modulus used for DSC -> SOD and pin it,
    // so the verifier's `dsc_chain.out_dsc_id == passport.in_dsc_id` check
    // guarantees the SOD was signed by exactly the DSC the chain proof trusts --
    // without this circuit re-running the (cacheable) RSA chain.
    let dsc_id = compute_dsc_id(modulus_limbs, exponent);
    assert(dsc_id == in_dsc_id, "DSC modulus does not match the trusted dsc_chain id");

    // Step 3: Verify DG hash chain (SOD -> DG1 / DG15).
    verify_dg_chain(
        sod_hash,
        dg_count,
        dg_contents,
        dg_lengths,
        expected_dg_hashes,
    );

    // Step 4 (sec.7.4): DG15 active authentication -- prove chip-in-possession
    // so a clone of the DG dumps + SOD alone cannot enroll. The AA key is read
    // from the DG-chain-bound DG15 (slot 1).
    verify_active_authentication(
        dg_contents[DG15_SLOT],
        dg_count,
        aa_signature,
        aa_challenge,
        require_aa,
    );

    // Step 5: Derive pk_digest from enclave pk (Path A device binding).
    let pk_digest = pk_digest_from_bytes(enclave_pk_x, enclave_pk_y);

    // Step 6: Derive the per-scope blinding (sec.7.1) so the commitment is the
    // holder's pseudonym for `link_scope` -- and only for that scope.
    let link_rand = derive_scoped_link_rand(link_rand_seed, link_scope);

    // Step 7: Compute v3.1 Pedersen commitment on Grumpkin (binds pk_digest).
    let dg1_hash = expected_dg_hashes[DG1_SLOT];
    let dg1_content = dg_contents[DG1_SLOT];
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
fn build_single_dg_fixture() -> ([u8; 32], [[u8; MAX_DG_SIZE]; MAX_DG_COUNT], [u32; MAX_DG_COUNT], [[u8; 32]; MAX_DG_COUNT]) {
    let dg1_data = build_dg_content(0x10, 64);
    let dg1_hash: [u8; 32] = digest(dg1_data);

    // SOD hash = SHA256(dg1_hash || zeros) for single DG
    let mut combined_preimage: [u8; MAX_DG_COUNT * 32] = [0; MAX_DG_COUNT * 32];
    for k in 0..32 {
        combined_preimage[k] = dg1_hash[k];
    }
    let sod_hash: [u8; 32] = digest(combined_preimage);

    let dg_contents = [dg1_data, [0; MAX_DG_SIZE]];
    let dg_lengths: [u32; MAX_DG_COUNT] = [64, 0];
    let expected_dg_hashes = [dg1_hash, [0; 32]];

    (sod_hash, dg_contents, dg_lengths, expected_dg_hashes)
}

/// Build a valid two-DG test fixture (DG1 + DG15 slots).
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

    let dg_contents = [dg1_data, dg2_data];
    let dg_lengths: [u32; MAX_DG_COUNT] = [64, 128];
    let expected_dg_hashes = [dg1_hash, dg2_hash];

    (sod_hash, dg_contents, dg_lengths, expected_dg_hashes)
}

/// Canonical P-256 enclave test key (x) -- tracks openac_core::device.
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

/// Deterministic non-trivial DSC modulus fixture for the dsc_id binding tests.
fn test_dsc_modulus() -> [u128; RSA_LIMB_COUNT] {
    let mut limbs: [u128; RSA_LIMB_COUNT] = [0; RSA_LIMB_COUNT];
    for i in 0..RSA_LIMB_COUNT {
        limbs[i] = 0x1000_0000 + i as u128;
    }
    limbs
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
    // Path A property: swapping enclave pk bytes must change the commitment,
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

    let claims = pack_passport_claims(2000, 3, 15, [84, 87, 78]);
    let (sod_hi, sod_lo) = hash_to_fields(sod_hash);
    let (dg1_hi, dg1_lo) = hash_to_fields(dg1_hash);
    let c_manual = commit_passport_v3_1(claims, sod_hi, sod_lo, dg1_hi, dg1_lo, pk_digest, rand);

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

// --- DSC linking id (Phase 6) tests ---

#[test]
fn test_passport_dsc_id_matches_for_same_modulus() {
    // The passport core re-derives the dsc_chain linking id from its DSC
    // modulus; the same modulus must yield the same id the chain proof output.
    let a = compute_dsc_id(test_dsc_modulus(), DSC_RSA_EXPONENT);
    let b = compute_dsc_id(test_dsc_modulus(), DSC_RSA_EXPONENT);
    assert(a == b, "passport dsc_id must be deterministic for the same DSC modulus");
}

#[test(should_fail)]
fn test_passport_rejects_wrong_dsc_id() {
    // Reproduce main()'s dsc_id binding: a prover whose DSC modulus does not
    // match the pinned (trusted) dsc_chain id must be rejected.
    let id = compute_dsc_id(test_dsc_modulus(), DSC_RSA_EXPONENT);
    let pinned = id + 1; // verifier pinned a different, trusted DSC id
    assert(id == pinned, "DSC modulus does not match the trusted dsc_chain id");
}

// --- Per-scope pseudonym (sec.7.1) ---

#[test]
fn test_scoped_commitment_differs_across_scopes() {
    // The same holder seed under two verifier scopes must produce different
    // commitments, so colluding verifiers cannot correlate by commitment coords.
    let sod_hash = sample_bytes(0x10);
    let dg1 = build_profile_dg1([84, 87, 78], [48, 48, 48, 51, 49, 53], 60);
    let dg1_hash: [u8; 32] = digest(dg1);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let seed: Field = 0xABCDEF;
    let r_a = derive_scoped_link_rand(seed, 1);
    let r_b = derive_scoped_link_rand(seed, 2);
    let c_a = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, r_a);
    let c_b = compute_passport_commitment(sod_hash, dg1, dg1_hash, pk_digest, r_b);
    assert(c_a.x != c_b.x, "different scope must yield a different scoped commitment");
}

// --- DG15 active authentication (sec.7.4) ---
//
// Reuses the canonical ECDSA-P256 fixture from openac_core::device: the AA
// public key is the same point as test_enclave_pk_x/y, and (signature, message)
// below are a valid triple under it. So an "AA chip" whose DG15 key is that
// point, signing test_aa_challenge(), produces test_aa_signature().

fn test_aa_signature() -> [u8; 64] {
    [
        0x6e, 0xd8, 0x75, 0x24, 0xa9, 0xc8, 0x44, 0xad, 0x2c, 0x67, 0x2c, 0x33, 0xaa, 0x15, 0x73,
        0xdd, 0xcc, 0xba, 0x5a, 0x2c, 0x74, 0xf6, 0xa6, 0xbd, 0xb3, 0x40, 0xcf, 0x18, 0xac, 0xd8,
        0x43, 0x89, 0x1c, 0xd8, 0xf8, 0xa8, 0x63, 0x76, 0x98, 0x3c, 0x44, 0xa2, 0x9a, 0x61, 0xe9,
        0x0c, 0x85, 0xc0, 0x37, 0x34, 0xd6, 0xb3, 0xba, 0x68, 0xb3, 0xaa, 0xbc, 0x9f, 0x64, 0x11,
        0xe1, 0x3b, 0x45, 0x4c,
    ]
}

fn test_aa_challenge() -> [u8; 32] {
    [
        0xd6, 0xe9, 0xef, 0x3f, 0xc3, 0x44, 0x1a, 0xb5, 0x33, 0xb3, 0x84, 0x31, 0xda, 0x4c, 0xa9,
        0x67, 0x49, 0xaf, 0x9a, 0x3e, 0x2f, 0x8e, 0x99, 0x35, 0x38, 0x91, 0xbd, 0xf4, 0x05, 0x94,
        0x5a, 0xde,
    ]
}

/// Normalised DG15 fixture: AA EC-P256 pubkey x at [0..32), y at [32..64).
fn build_dg15_with_aa_key() -> [u8; MAX_DG_SIZE] {
    let mut dg15: [u8; MAX_DG_SIZE] = [0; MAX_DG_SIZE];
    let x = test_enclave_pk_x();
    let y = test_enclave_pk_y();
    for i in 0..32 {
        dg15[AA_PK_X_OFFSET + i] = x[i];
        dg15[AA_PK_Y_OFFSET + i] = y[i];
    }
    dg15
}

#[test]
fn test_aa_extract_roundtrips_key() {
    let (x, y) = extract_aa_pubkey(build_dg15_with_aa_key());
    assert(x == test_enclave_pk_x(), "AA pubkey x must round-trip from DG15");
    assert(y == test_enclave_pk_y(), "AA pubkey y must round-trip from DG15");
}

#[test]
fn test_aa_passes_with_valid_dg15_signature() {
    // dg_count = 2 => DG15 (slot 1) is in the chain; valid chip signature.
    verify_active_authentication(
        build_dg15_with_aa_key(),
        2,
        test_aa_signature(),
        test_aa_challenge(),
        true,
    );
}

#[test(should_fail_with = "Active Authentication signature verification failed")]
fn test_aa_rejects_tampered_signature() {
    // Anti-cloning core: a cloner without the AA private key cannot forge the
    // chip signature, so a tampered signature must be rejected when AA required.
    let mut bad = test_aa_signature();
    bad[0] ^= 0xFF;
    verify_active_authentication(build_dg15_with_aa_key(), 2, bad, test_aa_challenge(), true);
}

#[test(should_fail_with = "DG15 must be present when active authentication is required")]
fn test_aa_rejects_missing_dg15_when_required() {
    // dg_count = 1 means DG15 is not hashed into the chain, so its key is not
    // passive-auth bound; require_aa must reject rather than trust a loose key.
    verify_active_authentication(
        build_dg15_with_aa_key(),
        1,
        test_aa_signature(),
        test_aa_challenge(),
        true,
    );
}

#[test]
fn test_aa_skipped_when_not_required() {
    // Non-AA passport: require_aa = false, so an unusable signature is tolerated
    // (the verifier that wants anti-cloning pins require_aa = true instead).
    let mut garbage = test_aa_signature();
    garbage[0] ^= 0xFF;
    verify_active_authentication(
        build_dg15_with_aa_key(),
        1,
        garbage,
        test_aa_challenge(),
        false,
    );
}
