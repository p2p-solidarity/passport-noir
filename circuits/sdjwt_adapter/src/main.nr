use std::ecdsa_secp256r1::verify_signature;
use sha256::digest;

use openac_core::commit::{commit_attributes, assert_commitment_eq, hash_to_fields, DOMAIN_SDJWT};

// OpenAC SD-JWT Adapter (Prepare Phase)
//
// Verifies an SD-JWT credential with ES256 (ECDSA P-256) signature and
// produces a Pedersen commitment for OpenAC linking.
//
// Paper C1 (prepare relation) for SD-JWT:
//   1. Assert parse_SD-JWT(S) = ({m_i}, {s_i}, {h_i}, sigma_I)
//   2. Assert h_i = SHA256(m_i || s_i) for all i
//   3. Assert ECDSA.verify(sigma_I, PK_I) = 1
//   + Compute Pedersen commitment C = Com(attrs; link_rand)
//
// SD-JWT structure:
//   - Header.Payload.Signature (JWS Compact)
//   - Each selective disclosure: base64url(SHA256(salt || claim_value))
//   - Signature: ES256 (ECDSA P-256 over SHA-256 of header.payload)

// Maximum number of SD-JWT disclosures supported
global MAX_DISCLOSURES: u32 = 8;
// Maximum bytes per claim value
global MAX_CLAIM_SIZE: u32 = 64;
// Salt size for SD-JWT (typically 128-bit = 16 bytes)
global SALT_SIZE: u32 = 16;

fn main(
    // === ECDSA ES256 signature verification inputs ===
    // SHA-256 hash of the JWT header.payload (signed content)
    jwt_payload_hash: [u8; 32],
    // ECDSA signature (r || s, 32 bytes each)
    signature: [u8; 64],

    // === Issuer public key (public - verifier checks against trusted registry) ===
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],

    // === SD-JWT claim verification inputs ===
    // Number of disclosures actually present
    disclosure_count: u8,
    // Salt for each disclosure
    disclosure_salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES],
    // Claim values (padded to MAX_CLAIM_SIZE each)
    claim_values: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES],
    // Actual length of each claim value
    claim_lengths: [u32; MAX_DISCLOSURES],
    // Expected disclosure hashes from the SD-JWT _sd array
    expected_disclosure_hashes: [[u8; 32]; MAX_DISCLOSURES],

    // === OpenAC commitment inputs ===
    link_rand: Field,

    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // -------------------------------------------------------
    // Step 1: Verify ECDSA ES256 signature
    // Paper: "Assert ECDSA.verify(sigma_I, PK_I) = 1"
    // -------------------------------------------------------
    let sig_valid = verify_signature(
        issuer_pk_x,
        issuer_pk_y,
        signature,
        jwt_payload_hash,
    );
    assert(sig_valid, "SD-JWT ES256 signature verification failed");

    // -------------------------------------------------------
    // Step 2: Verify disclosure hashes
    // Paper: "Assert h_i = SHA256(m_i, s_i) for all i"
    // SD-JWT: each disclosure hash = SHA256(salt || claim_value)
    // -------------------------------------------------------
    assert(disclosure_count as u32 <= MAX_DISCLOSURES, "Too many disclosures");

    let mut combined_preimage: [u8; MAX_DISCLOSURES * 32] = [0; MAX_DISCLOSURES * 32];

    for i in 0..MAX_DISCLOSURES {
        if (i as u8) < disclosure_count {
            // Build preimage: salt || length_be(4) || claim_value (padded)
            // Length prefix prevents zero-padding ambiguity (CRITICAL-1 fix)
            let mut preimage: [u8; SALT_SIZE + 4 + MAX_CLAIM_SIZE] = [0; SALT_SIZE + 4 + MAX_CLAIM_SIZE];
            let len = claim_lengths[i];
            assert(len <= MAX_CLAIM_SIZE as u32, "Claim length exceeds maximum");

            for j in 0..SALT_SIZE {
                preimage[j] = disclosure_salts[i][j];
            }
            // Encode claim length as 4-byte big-endian
            preimage[SALT_SIZE] = ((len >> 24) & 0xFF) as u8;
            preimage[SALT_SIZE + 1] = ((len >> 16) & 0xFF) as u8;
            preimage[SALT_SIZE + 2] = ((len >> 8) & 0xFF) as u8;
            preimage[SALT_SIZE + 3] = (len & 0xFF) as u8;
            for j in 0..MAX_CLAIM_SIZE {
                if (j as u32) < len {
                    preimage[SALT_SIZE + 4 + j] = claim_values[i][j];
                }
            }

            let computed_hash: [u8; 32] = digest(preimage);

            for k in 0..32 {
                assert(
                    computed_hash[k] == expected_disclosure_hashes[i][k],
                    "SD-JWT disclosure hash mismatch",
                );
            }

            for k in 0..32 {
                combined_preimage[i * 32 + k] = computed_hash[k];
            }
        }
    }

    // -------------------------------------------------------
    // Step 3: Compute Pedersen commitment
    // Standardize SD-JWT data into attr_hash for generic OpenAC
    // -------------------------------------------------------
    let combined_hash: [u8; 32] = digest(combined_preimage);
    let (attr_hi, attr_lo) = hash_to_fields(combined_hash);

    let commitment = commit_attributes(DOMAIN_SDJWT, attr_hi, attr_lo, link_rand);
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);
}

// ============================================================
// Tests
// ============================================================

#[test(should_fail)]
fn test_invalid_signature_fails() {
    let bad_sig: [u8; 64] = [0; 64];
    let bad_pk_x: [u8; 32] = [1; 32];
    let bad_pk_y: [u8; 32] = [2; 32];
    let msg_hash: [u8; 32] = [3; 32];

    let salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES] = [[0; SALT_SIZE]; MAX_DISCLOSURES];
    let claims: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES] = [[0; MAX_CLAIM_SIZE]; MAX_DISCLOSURES];
    let lengths: [u32; MAX_DISCLOSURES] = [0; MAX_DISCLOSURES];
    let hashes: [[u8; 32]; MAX_DISCLOSURES] = [[0; 32]; MAX_DISCLOSURES];

    main(
        msg_hash,
        bad_sig,
        bad_pk_x,
        bad_pk_y,
        0,
        salts,
        claims,
        lengths,
        hashes,
        42,
        0,
        0,
    );
}
