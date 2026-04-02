use noir_rsa::rsa::verify_sha256_pkcs1v15;
use bignum::RuntimeBigNum;
use bignum::params::BigNumParams;
use sha256::digest;

use openac_core::commit::{commit_attributes, assert_commitment_eq, hash_to_fields, DOMAIN_PASSPORT};

// OpenAC Passport Adapter (Prepare Phase)
//
// Combines:
//   1. RSA-2048 signature verification (DSC -> SOD)  [from passport_verifier]
//   2. DG hash chain verification (SOD -> DG1)        [from data_integrity]
//   3. Pedersen commitment on Grumpkin                 [from openac_core]
//
// Paper C1 (prepare relation):
//   "Assert parse(S) = ({m_i}, {s_i}, {h_i}, sigma_I)"
//   "Assert h_i = SHA256(m_i, s_i)"
//   "Assert ECDSA.verify(sigma_I, PK_I) = 1"  [RSA for passport]
//   + Compute Pedersen commitment C = Com(attrs; link_rand)
//
// Public outputs:
//   - modulus_limbs: RSA public key (issuer identity)
//   - out_commitment_x, out_commitment_y: Grumpkin Pedersen commitment point
//
// The commitment (C.x, C.y) is what links this prepare proof to the show proof.
// Verifier checks: prepare.out_commitment == show.out_commitment

global MAX_DG_COUNT: u32 = 4;
global MAX_DG_SIZE: u32 = 512;

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

    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // -------------------------------------------------------
    // Step 1: Verify RSA-2048 signature (DSC -> SOD)
    // Paper: "Assert SIG.verify(sigma_I, PK_I) = 1"
    // -------------------------------------------------------
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, redc_limbs);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature_limbs };
    assert(
        verify_sha256_pkcs1v15(sod_hash, signature, exponent),
        "Passport DSC signature verification failed",
    );

    // -------------------------------------------------------
    // Step 2: Verify DG hash chain (SOD -> DG1..DG4)
    // Paper: "Assert h_i = SHA256(m_i, s_i) for all i"
    // -------------------------------------------------------
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
                assert(
                    computed_hash[k] == expected_dg_hashes[i][k],
                    "Data group hash mismatch",
                );
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

    // -------------------------------------------------------
    // Step 3: Compute Pedersen commitment
    // Paper: Com(m; r) = product(g_i^{m_i}) * h^r
    // Commit to (sod_hash, mrz_hash) under DOMAIN_PASSPORT
    // -------------------------------------------------------

    // Extract MRZ hash from DG1 (first data group = MRZ data)
    // DG1 content hashed = mrz attestation
    let mrz_hash = expected_dg_hashes[0];

    // Combine sod_hash + mrz_hash into a single attr_hash: H(sod_hash || mrz_hash)
    // This gives us a standardized 256-bit attribute fingerprint
    let mut combined: [u8; 64] = [0; 64];
    for i in 0..32 {
        combined[i] = sod_hash[i];
        combined[32 + i] = mrz_hash[i];
    }
    let attr_combined: [u8; 32] = digest(combined);
    let (attr_hi, attr_lo) = hash_to_fields(attr_combined);

    // Compute Pedersen commitment on Grumpkin
    let commitment = commit_attributes(DOMAIN_PASSPORT, attr_hi, attr_lo, link_rand);
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);
}
