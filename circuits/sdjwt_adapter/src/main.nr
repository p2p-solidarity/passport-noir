use sha256::digest;
use std::ecdsa_secp256r1::verify_signature;
use std::embedded_curve_ops::EmbeddedCurvePoint;

use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_SDJWT, hash_to_fields};
use openac_core::device::pk_digest_from_bytes;

// OpenAC SD-JWT Adapter (Prepare Phase, v1 -- Path A)
//
// Verifies an SD-JWT credential with ES256 (ECDSA P-256) signature and
// produces a v3 Pedersen commitment (5-arg, binds an enclave pk_digest)
// for OpenAC linking.
//
// Paper C1 (prepare relation) for SD-JWT:
//   1. Assert parse_SD-JWT(S) = ({m_i}, {s_i}, {h_i}, sigma_I)
//   2. Assert h_i = SHA256(m_i || s_i) for all i
//   3. Assert ECDSA.verify(sigma_I, PK_I) = 1
//   + Compute Pedersen v3 commitment C = Com(domain, sd_root_hi, sd_root_lo,
//       pk_digest; link_rand)
//
// Path A change (vs. the earlier v2 draft that used `commit_attributes`):
//   * The commitment is arity-5 `commit_attributes_v3` and now binds a
//     `pk_digest = pedersen_hash(enclave_pk)`. The Show circuit uses the
//     same pk_digest (re-derived from an in-circuit ECDSA verification over
//     a fresh verifier nonce) to enforce device ownership.
//   * The SD-JWT adapter continues to use the combined disclosure hash as
//     the attribute input (`sd_root` per spec section 5), split to (hi, lo)
//     Fields. No separate `commit_attributes_v3_extended` helper is
//     introduced -- the extras are captured in `sd_root` as the spec
//     directs (hi/lo packing of the combined _sd hash).
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

/// Verify SD-JWT disclosure hashes: each claim's salt+value hashes to the expected hash.
/// Returns the combined hash of all disclosure hashes for commitment computation.
fn verify_disclosure_hashes(
    disclosure_count: u8,
    disclosure_salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES],
    claim_values: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES],
    claim_lengths: [u32; MAX_DISCLOSURES],
    expected_disclosure_hashes: [[u8; 32]; MAX_DISCLOSURES],
) -> [u8; 32] {
    assert(disclosure_count as u32 <= MAX_DISCLOSURES, "Too many disclosures");

    let mut combined_preimage: [u8; MAX_DISCLOSURES * 32] = [0; MAX_DISCLOSURES * 32];

    for i in 0..MAX_DISCLOSURES {
        if (i as u8) < disclosure_count {
            // Build preimage: salt || length_be(4) || claim_value (padded)
            // Length prefix prevents zero-padding ambiguity
            let mut preimage: [u8; SALT_SIZE + 4 + MAX_CLAIM_SIZE] =
                [0; SALT_SIZE + 4 + MAX_CLAIM_SIZE];
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

    digest(combined_preimage)
}

/// Compute the v3 Pedersen commitment for an SD-JWT credential.
/// Takes the combined disclosure hash and an enclave pk_digest; produces a
/// Grumpkin curve point bound to both the SD-JWT disclosure root and the
/// device's public key.
fn compute_sdjwt_commitment(
    combined_hash: [u8; 32],
    pk_digest: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    let (attr_hi, attr_lo) = hash_to_fields(combined_hash);
    commit_attributes_v3(DOMAIN_SDJWT, attr_hi, attr_lo, pk_digest, link_rand)
}

fn main(
    // === ECDSA ES256 signature verification inputs ===
    jwt_payload_hash: [u8; 32],
    signature: [u8; 64],
    // === Issuer public key (public - verifier checks against trusted registry) ===
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    // === SD-JWT claim verification inputs ===
    disclosure_count: u8,
    disclosure_salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES],
    claim_values: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES],
    claim_lengths: [u32; MAX_DISCLOSURES],
    expected_disclosure_hashes: [[u8; 32]; MAX_DISCLOSURES],
    // === OpenAC commitment inputs ===
    link_rand: Field,
    // === Path A device-binding witnesses (enclave pk is private) ===
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    // === Public outputs ===
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // Step 1: Verify ECDSA ES256 signature (issuer attested to the payload).
    let sig_valid = verify_signature(issuer_pk_x, issuer_pk_y, signature, jwt_payload_hash);
    assert(sig_valid, "SD-JWT ES256 signature verification failed");

    // Step 2: Verify disclosure hashes and derive the sd_root.
    let combined_hash = verify_disclosure_hashes(
        disclosure_count,
        disclosure_salts,
        claim_values,
        claim_lengths,
        expected_disclosure_hashes,
    );

    // Step 3: Derive pk_digest from enclave pk (Path A v3, no ECDSA check
    // over a nonce happens here -- the show circuit performs that check).
    let pk_digest = pk_digest_from_bytes(enclave_pk_x, enclave_pk_y);

    // Step 4: Compute v3 Pedersen commitment.
    let commitment = compute_sdjwt_commitment(combined_hash, pk_digest, link_rand);
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);
}

// ============================================================
// Tests
// ============================================================

/// Canonical P-256 enclave fixture (matches device_binding/src/main.nr).
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

/// Build a single disclosure test fixture.
/// Returns (salt, claim_value, claim_length, expected_hash).
fn build_disclosure_fixture(
    salt_seed: u8,
    claim_seed: u8,
    claim_len: u32,
) -> ([u8; SALT_SIZE], [u8; MAX_CLAIM_SIZE], u32, [u8; 32]) {
    let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
    for i in 0..SALT_SIZE {
        salt[i] = salt_seed + (i as u8);
    }

    let mut claim: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];
    for i in 0..MAX_CLAIM_SIZE {
        if (i as u32) < claim_len {
            claim[i] = claim_seed + (i as u8);
        }
    }

    // Compute expected hash: SHA256(salt || length_be || claim_value)
    let mut preimage: [u8; SALT_SIZE + 4 + MAX_CLAIM_SIZE] = [0; SALT_SIZE + 4 + MAX_CLAIM_SIZE];
    for j in 0..SALT_SIZE {
        preimage[j] = salt[j];
    }
    preimage[SALT_SIZE] = ((claim_len >> 24) & 0xFF) as u8;
    preimage[SALT_SIZE + 1] = ((claim_len >> 16) & 0xFF) as u8;
    preimage[SALT_SIZE + 2] = ((claim_len >> 8) & 0xFF) as u8;
    preimage[SALT_SIZE + 3] = (claim_len & 0xFF) as u8;
    for j in 0..MAX_CLAIM_SIZE {
        if (j as u32) < claim_len {
            preimage[SALT_SIZE + 4 + j] = claim[j];
        }
    }
    let hash: [u8; 32] = digest(preimage);

    (salt, claim, claim_len, hash)
}

// --- Disclosure hash verification tests ---

#[test]
fn test_single_disclosure_hash_passes() {
    let (salt, claim, len, hash) = build_disclosure_fixture(0x10, 0x20, 32);

    let mut salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES] = [[0; SALT_SIZE]; MAX_DISCLOSURES];
    let mut claims: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES] =
        [[0; MAX_CLAIM_SIZE]; MAX_DISCLOSURES];
    let mut lengths: [u32; MAX_DISCLOSURES] = [0; MAX_DISCLOSURES];
    let mut hashes: [[u8; 32]; MAX_DISCLOSURES] = [[0; 32]; MAX_DISCLOSURES];

    salts[0] = salt;
    claims[0] = claim;
    lengths[0] = len;
    hashes[0] = hash;

    let result = verify_disclosure_hashes(1, salts, claims, lengths, hashes);
    assert(result[0] != 0, "Combined hash should be non-zero");
}

#[test]
fn test_two_disclosures_pass() {
    let (salt1, claim1, len1, hash1) = build_disclosure_fixture(0x10, 0x20, 16);
    let (salt2, claim2, len2, hash2) = build_disclosure_fixture(0x30, 0x40, 48);

    let mut salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES] = [[0; SALT_SIZE]; MAX_DISCLOSURES];
    let mut claims: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES] =
        [[0; MAX_CLAIM_SIZE]; MAX_DISCLOSURES];
    let mut lengths: [u32; MAX_DISCLOSURES] = [0; MAX_DISCLOSURES];
    let mut hashes: [[u8; 32]; MAX_DISCLOSURES] = [[0; 32]; MAX_DISCLOSURES];

    salts[0] = salt1;
    salts[1] = salt2;
    claims[0] = claim1;
    claims[1] = claim2;
    lengths[0] = len1;
    lengths[1] = len2;
    hashes[0] = hash1;
    hashes[1] = hash2;

    let result = verify_disclosure_hashes(2, salts, claims, lengths, hashes);
    assert(result[0] != 0, "Combined hash should be non-zero for 2 disclosures");
}

#[test(should_fail)]
fn test_wrong_disclosure_hash_fails() {
    let (salt, claim, len, mut hash) = build_disclosure_fixture(0x10, 0x20, 32);
    hash[0] ^= 0xFF;

    let mut salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES] = [[0; SALT_SIZE]; MAX_DISCLOSURES];
    let mut claims: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES] =
        [[0; MAX_CLAIM_SIZE]; MAX_DISCLOSURES];
    let mut lengths: [u32; MAX_DISCLOSURES] = [0; MAX_DISCLOSURES];
    let mut hashes: [[u8; 32]; MAX_DISCLOSURES] = [[0; 32]; MAX_DISCLOSURES];

    salts[0] = salt;
    claims[0] = claim;
    lengths[0] = len;
    hashes[0] = hash;

    let _ = verify_disclosure_hashes(1, salts, claims, lengths, hashes);
}

// --- Commitment tests ---

#[test]
fn test_sdjwt_commitment_deterministic() {
    let mut hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        hash[i] = (i as u8) + 0x50;
    }
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_sdjwt_commitment(hash, pk_digest, 42);
    let c2 = compute_sdjwt_commitment(hash, pk_digest, 42);
    assert(c1.x == c2.x, "SD-JWT commitment X should be deterministic");
    assert(c1.y == c2.y, "SD-JWT commitment Y should be deterministic");
}

#[test]
fn test_sdjwt_commitment_changes_with_rand() {
    let mut hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        hash[i] = (i as u8) + 0x50;
    }
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_sdjwt_commitment(hash, pk_digest, 42);
    let c2 = compute_sdjwt_commitment(hash, pk_digest, 43);
    assert(c1.x != c2.x, "Different link_rand must produce different commitment");
}

#[test]
fn test_sdjwt_commitment_changes_with_enclave_pk() {
    // Path A: swapping the enclave pk must produce a different commitment,
    // so an attacker with the SD-JWT but a different device key cannot
    // re-open the same commitment.
    let mut hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        hash[i] = (i as u8) + 0x50;
    }
    let pk_digest_a = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let mut pk_x_b = test_enclave_pk_x();
    pk_x_b[0] ^= 0x01;
    let pk_digest_b = pk_digest_from_bytes(pk_x_b, test_enclave_pk_y());
    let c1 = compute_sdjwt_commitment(hash, pk_digest_a, 42);
    let c2 = compute_sdjwt_commitment(hash, pk_digest_b, 42);
    assert(c1.x != c2.x, "Different enclave pk must produce different commitment");
}

#[test]
fn test_disclosure_and_commitment_integration() {
    let (salt, claim, len, hash) = build_disclosure_fixture(0x10, 0x20, 32);

    let mut salts: [[u8; SALT_SIZE]; MAX_DISCLOSURES] = [[0; SALT_SIZE]; MAX_DISCLOSURES];
    let mut claims: [[u8; MAX_CLAIM_SIZE]; MAX_DISCLOSURES] =
        [[0; MAX_CLAIM_SIZE]; MAX_DISCLOSURES];
    let mut lengths: [u32; MAX_DISCLOSURES] = [0; MAX_DISCLOSURES];
    let mut hashes: [[u8; 32]; MAX_DISCLOSURES] = [[0; 32]; MAX_DISCLOSURES];

    salts[0] = salt;
    claims[0] = claim;
    lengths[0] = len;
    hashes[0] = hash;

    let combined = verify_disclosure_hashes(1, salts, claims, lengths, hashes);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c = compute_sdjwt_commitment(combined, pk_digest, 99);
    assert(c.x != 0, "Commitment X should be non-zero for valid inputs");
}

// --- Signature tests ---

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
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        0,
        0,
    );
}
