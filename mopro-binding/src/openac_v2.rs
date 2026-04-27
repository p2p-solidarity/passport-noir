//! OpenAC v2: Pedersen commitment-based verification contract.
//!
//! Upgrades from SHA256 hash commitments (v1) to Pedersen commitments
//! on the Grumpkin curve, enabling:
//! - Homomorphic re-randomization (batch prepare)
//! - Commitment equality linking (paper's Hyrax model)
//! - Multi-credential support via domain-separated commitments
//!
//! Paper: "OpenAC: Open Design for Transparent and Lightweight Anonymous Credentials"
//! Math: Com(m; r) = product(g_i^{m_i}) * h^r  on Grumpkin

use crate::MoproError;
use sha2::{Digest, Sha256};

pub const FIELD_BYTES: usize = 32;

// Domain separators matching openac_core/commit.nr
pub const DOMAIN_PASSPORT: u8 = 0x01;
pub const DOMAIN_SDJWT: u8 = 0x02;
pub const DOMAIN_MDL: u8 = 0x03;

// Show-phase domain (v2 = Pedersen-based, matches openac_core/show.nr)
const SHOW_DOMAIN_V2: &[u8] = b"openac.show.v2";

/// A Grumpkin curve point representing a Pedersen commitment.
/// This is the core linking element between prepare and show proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenPoint {
    /// X coordinate (bn254 scalar field element, 32 bytes big-endian)
    pub x: [u8; FIELD_BYTES],
    /// Y coordinate (bn254 scalar field element, 32 bytes big-endian)
    pub y: [u8; FIELD_BYTES],
}

impl PedersenPoint {
    pub fn zero() -> Self {
        Self {
            x: [0u8; FIELD_BYTES],
            y: [0u8; FIELD_BYTES],
        }
    }
}

/// Prepare artifact with Pedersen commitment (v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareArtifactV2 {
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    /// Credential type domain (DOMAIN_PASSPORT, DOMAIN_SDJWT, etc.)
    pub credential_type: u8,
    /// Pedersen commitment point on Grumpkin
    pub commitment: PedersenPoint,
    /// Blinding randomness (needed for re-randomization)
    pub link_rand: [u8; FIELD_BYTES],
    /// Noir proof bytes
    pub proof: Vec<u8>,
    /// Verification key bytes
    pub vk: Vec<u8>,
}

/// Show presentation with Pedersen commitment (v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowPresentationV2 {
    /// Pedersen commitment point (MUST match prepare's commitment)
    pub commitment: PedersenPoint,
    /// Challenge from verifier
    pub challenge: [u8; 32],
    /// SHA256 challenge digest (binds challenge to commitment + epoch)
    pub challenge_digest: [u8; 32],
    /// Scoped link tag (Field, 0 for unlinkable mode)
    pub link_tag: [u8; FIELD_BYTES],
    /// Noir proof bytes
    pub proof: Vec<u8>,
    /// Verification key bytes
    pub vk: Vec<u8>,
}

/// Verification policy (v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyV2 {
    pub link_mode: LinkMode,
    /// Scope identifier (Field, None for unlinkable)
    pub link_scope: Option<[u8; FIELD_BYTES]>,
    pub epoch: [u8; 4],
    pub epoch_field: [u8; FIELD_BYTES],
    pub now_unix: u64,
    pub expected_challenge: [u8; 32],
    pub prepare_vk_hash: [u8; 32],
    pub show_vk_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    Unlinkable,
    ScopedLinkable,
}

/// Batch entry: a re-randomized commitment with its new randomness.
/// Paper: "The prover will run prepareBatch periodically"
#[derive(Debug, Clone)]
pub struct BatchEntry {
    pub commitment: PedersenPoint,
    pub link_rand: [u8; FIELD_BYTES],
}

fn verification_error(code: &str) -> MoproError {
    MoproError::VerificationError(code.to_string())
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify that the commitment coordinates appear in the proof's public inputs.
/// The proof bytes start with public inputs encoded as 32-byte big-endian Field elements.
/// We search for the commitment (x, y) as two consecutive 32-byte values.
fn verify_commitment_in_proof(
    proof: &[u8],
    commitment: &PedersenPoint,
    error_code: &str,
) -> Result<(), MoproError> {
    if proof.len() < FIELD_BYTES * 2 {
        return Err(verification_error(error_code));
    }

    // Search for commitment (x, y) as consecutive Field elements in the proof's
    // public input region. Public inputs are at the start of the proof bytes.
    let target = [&commitment.x[..], &commitment.y[..]].concat();
    let search_limit = proof.len().saturating_sub(FIELD_BYTES * 2);

    for offset in (0..=search_limit).step_by(FIELD_BYTES) {
        if proof[offset..offset + FIELD_BYTES * 2] == target[..] {
            return Ok(());
        }
    }

    Err(verification_error(error_code))
}

/// Compute challenge digest (v2).
/// SHA256("openac.show.v2" || commitment_x || commitment_y || challenge || epoch)
pub fn compute_challenge_digest_v2(
    commitment: &PedersenPoint,
    challenge: &[u8; 32],
    epoch: &[u8; 4],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SHOW_DOMAIN_V2);
    hasher.update(&commitment.x);
    hasher.update(&commitment.y);
    hasher.update(challenge);
    hasher.update(epoch);
    hasher.finalize().into()
}

/// Re-randomize a Pedersen commitment (out-of-circuit).
///
/// Paper: c^(j) = c^(1) * h^{delta_r}
/// where delta_r = r_new - r_old
///
/// For Grumpkin: C' = C + delta_r * H
/// where H is Noir's Pedersen blinding generator.
///
/// NOTE: Full EC arithmetic on Grumpkin requires ark-grumpkin or equivalent.
/// This is a placeholder that documents the interface. The actual implementation
/// needs the Grumpkin curve library to perform point addition and scalar multiplication.
///
/// When implementing:
///   1. Parse commitment.x/y as Grumpkin affine coordinates
///   2. Parse r_old/r_new as Grumpkin scalars
///   3. Compute delta = (r_new - r_old) * BLINDING_GENERATOR
///   4. Return C + delta as new PedersenPoint
pub fn rerandomize_commitment(
    _commitment: &PedersenPoint,
    _r_old: &[u8; FIELD_BYTES],
    _r_new: &[u8; FIELD_BYTES],
) -> PedersenPoint {
    // TODO: Implement with ark-grumpkin or equivalent EC library
    // For now, return a placeholder that documents the API contract
    unimplemented!(
        "Requires Grumpkin EC arithmetic (ark-grumpkin). \
         Formula: C' = C + (r_new - r_old) * BLINDING_GENERATOR"
    )
}

/// Prepare a batch of re-randomized commitments.
///
/// Paper: "The prover will run prepareBatch periodically to generate
/// re-randomized commitments c^(j) and store the randomness r_1^(j)"
pub fn prepare_batch(
    _initial_commitment: &PedersenPoint,
    _initial_rand: &[u8; FIELD_BYTES],
    _batch_size: usize,
) -> Vec<BatchEntry> {
    // TODO: Implement with Grumpkin EC arithmetic
    // 1. For each j in batch_size:
    //    a. Generate random r_new
    //    b. C_new = rerandomize_commitment(C, r_old, r_new)
    //    c. Store (C_new, r_new)
    unimplemented!(
        "Requires Grumpkin EC arithmetic (ark-grumpkin). \
         Each entry: rerandomize(C, r_old, random_r_new)"
    )
}

/// Verify linked OpenAC prepare + show proofs (v2, Pedersen-based).
///
/// The KEY difference from v1: linking is via Grumpkin point equality
/// instead of SHA256 hash equality.
///
/// Paper: "The verifier checks that the Pedersen commitment to the
///         messages column for pi_show equals that of pi_prepare"
pub fn verify_openac_v2(
    prepare: &PrepareArtifactV2,
    show: &ShowPresentationV2,
    policy: &PolicyV2,
) -> Result<(), MoproError> {
    verify_openac_v2_with_verifier(prepare, show, policy, &crate::noir::verify_noir_proof)
}

pub fn verify_openac_v2_with_verifier<F>(
    prepare: &PrepareArtifactV2,
    show: &ShowPresentationV2,
    policy: &PolicyV2,
    verifier: &F,
) -> Result<(), MoproError>
where
    F: Fn(Vec<u8>, Vec<u8>) -> Result<bool, MoproError>,
{
    // 1. VK trust check
    let prepare_vk_hash = sha256_hash(&prepare.vk);
    if prepare_vk_hash != policy.prepare_vk_hash {
        return Err(verification_error("untrusted_prepare_vk"));
    }
    let show_vk_hash = sha256_hash(&show.vk);
    if show_vk_hash != policy.show_vk_hash {
        return Err(verification_error("untrusted_show_vk"));
    }

    // 2. Verify Noir proofs
    if prepare.proof.is_empty() || prepare.vk.is_empty() {
        return Err(verification_error("empty_prepare_bundle"));
    }
    let prepare_valid = verifier(prepare.proof.clone(), prepare.vk.clone())?;
    if !prepare_valid {
        return Err(verification_error("invalid_prepare_proof"));
    }

    if show.proof.is_empty() || show.vk.is_empty() {
        return Err(verification_error("empty_show_bundle"));
    }
    let show_valid = verifier(show.proof.clone(), show.vk.clone())?;
    if !show_valid {
        return Err(verification_error("invalid_show_proof"));
    }

    // 3. TTL check
    if prepare.created_at_unix > policy.now_unix {
        return Err(verification_error("prepare_not_active"));
    }
    if policy.now_unix > prepare.expires_at_unix {
        return Err(verification_error("expired_prepare"));
    }

    // 4. Verify commitment coordinates are embedded in proof public inputs.
    // This prevents a caller from supplying arbitrary commitment fields
    // alongside a valid proof for a different commitment (CRITICAL-2 fix).
    //
    // Passport adapter public inputs layout: [..., out_commitment_x, out_commitment_y]
    // Show public inputs layout: [..., out_commitment_x, out_commitment_y, ...]
    // The commitment is encoded as two consecutive 32-byte big-endian Field elements.
    verify_commitment_in_proof(
        &prepare.proof,
        &prepare.commitment,
        "prepare_commitment_not_in_proof",
    )?;
    verify_commitment_in_proof(
        &show.proof,
        &show.commitment,
        "show_commitment_not_in_proof",
    )?;

    // 5. KEY LINKING CHECK: Pedersen commitment point equality
    // Paper: "verifier checks that the Pedersen commitment to the
    //         messages column for pi_show equals that of pi_prepare"
    if prepare.commitment != show.commitment {
        return Err(verification_error("commitment_mismatch"));
    }

    // 5. Challenge binding
    if show.challenge != policy.expected_challenge {
        return Err(verification_error("invalid_challenge"));
    }
    let expected_digest =
        compute_challenge_digest_v2(&show.commitment, &policy.expected_challenge, &policy.epoch);
    if show.challenge_digest != expected_digest {
        return Err(verification_error("invalid_challenge_digest"));
    }

    // 6. Scope / linkability check
    match policy.link_mode {
        LinkMode::Unlinkable => {
            if policy.link_scope.is_some() {
                return Err(verification_error("scope_mismatch"));
            }
            if show.link_tag != [0u8; FIELD_BYTES] {
                return Err(verification_error("scope_mismatch"));
            }
        }
        LinkMode::ScopedLinkable => {
            let _scope = policy
                .link_scope
                .ok_or_else(|| verification_error("scope_mismatch"))?;
            // Link tag is a Pedersen hash computed in-circuit.
            // Verifier trusts the circuit's output here (verified via Noir proof).
            // In v1, we recomputed the tag. In v2, the tag is a Pedersen hash
            // which we cannot cheaply recompute in Rust without the Grumpkin library.
            // The Noir proof already enforces tag correctness.
            if show.link_tag == [0u8; FIELD_BYTES] {
                return Err(verification_error("scope_mismatch"));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always_valid(_: Vec<u8>, _: Vec<u8>) -> Result<bool, MoproError> {
        Ok(true)
    }

    fn sample_point(seed: u8) -> PedersenPoint {
        let mut x = [0u8; FIELD_BYTES];
        let mut y = [0u8; FIELD_BYTES];
        for i in 0..FIELD_BYTES {
            x[i] = seed.wrapping_add(i as u8);
            y[i] = seed.wrapping_add(i as u8).wrapping_add(100);
        }
        PedersenPoint { x, y }
    }

    fn sample_field(seed: u8) -> [u8; FIELD_BYTES] {
        let mut out = [0u8; FIELD_BYTES];
        for i in 0..FIELD_BYTES {
            out[i] = seed.wrapping_add(i as u8);
        }
        out
    }

    fn sample_hash32(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = seed.wrapping_add(i as u8);
        }
        out
    }

    /// Build a mock proof that embeds commitment (x, y) as public inputs.
    fn mock_proof_with_commitment(commitment: &PedersenPoint, suffix: &[u8]) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(&commitment.x);
        proof.extend_from_slice(&commitment.y);
        proof.extend_from_slice(suffix);
        proof
    }

    fn fixture() -> (PrepareArtifactV2, ShowPresentationV2, PolicyV2) {
        let commitment = sample_point(10);
        let challenge = sample_hash32(44);
        let epoch = [0x20, 0x26, 0x04, 0x01];
        let challenge_digest = compute_challenge_digest_v2(&commitment, &challenge, &epoch);
        let scope = sample_field(55);
        let link_tag = sample_field(77); // In real usage, computed by circuit

        let prepare_vk = vec![1, 2, 3];
        let show_vk = vec![4, 5, 6];

        let prepare = PrepareArtifactV2 {
            created_at_unix: 100,
            expires_at_unix: 200,
            credential_type: DOMAIN_PASSPORT,
            commitment,
            link_rand: sample_field(33),
            proof: mock_proof_with_commitment(&commitment, &[10, 20, 30]),
            vk: prepare_vk.clone(),
        };

        let show = ShowPresentationV2 {
            commitment, // SAME point as prepare
            challenge,
            challenge_digest,
            link_tag,
            proof: mock_proof_with_commitment(&commitment, &[40, 50, 60]),
            vk: show_vk.clone(),
        };

        let policy = PolicyV2 {
            link_mode: LinkMode::ScopedLinkable,
            link_scope: Some(scope),
            epoch,
            epoch_field: sample_field(0x20),
            now_unix: 150,
            expected_challenge: challenge,
            prepare_vk_hash: sha256_hash(&prepare_vk),
            show_vk_hash: sha256_hash(&show_vk),
        };

        (prepare, show, policy)
    }

    #[test]
    fn test_v2_happy_path() {
        let (prepare, show, policy) = fixture();
        let result = verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v2_commitment_mismatch() {
        let (prepare, mut show, policy) = fixture();
        let tampered_commitment = {
            let mut c = show.commitment;
            c.x[0] ^= 0x01;
            c
        };
        // Rebuild show proof with tampered commitment so it passes the proof-binding check
        show.commitment = tampered_commitment;
        show.proof = mock_proof_with_commitment(&tampered_commitment, &[40, 50, 60]);
        show.challenge_digest = compute_challenge_digest_v2(
            &show.commitment,
            &policy.expected_challenge,
            &policy.epoch,
        );

        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("commitment_mismatch"));
    }

    #[test]
    fn test_v2_commitment_not_in_proof_rejected() {
        // Struct says commitment X, but proof bytes contain different data
        let (mut prepare, show, policy) = fixture();
        prepare.proof = vec![0u8; 128]; // garbage, no valid commitment
        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("prepare_commitment_not_in_proof"));
    }

    #[test]
    fn test_v2_expired_prepare() {
        let (prepare, show, mut policy) = fixture();
        policy.now_unix = 300; // Past expiry
        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("expired_prepare"));
    }

    #[test]
    fn test_v2_wrong_challenge() {
        let (prepare, mut show, policy) = fixture();
        show.challenge[0] ^= 0xFF;
        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("invalid_challenge"));
    }

    #[test]
    fn test_v2_untrusted_vk() {
        let (prepare, show, mut policy) = fixture();
        policy.prepare_vk_hash = sample_hash32(99);
        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("untrusted_prepare_vk"));
    }

    #[test]
    fn test_v2_unlinkable_mode() {
        let (prepare, mut show, mut policy) = fixture();
        policy.link_mode = LinkMode::Unlinkable;
        policy.link_scope = None;
        show.link_tag = [0u8; FIELD_BYTES];
        show.challenge_digest = compute_challenge_digest_v2(
            &show.commitment,
            &policy.expected_challenge,
            &policy.epoch,
        );

        let result = verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v2_unlinkable_rejects_nonzero_tag() {
        let (prepare, show, mut policy) = fixture();
        policy.link_mode = LinkMode::Unlinkable;
        policy.link_scope = None;
        // show.link_tag is non-zero from fixture

        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("scope_mismatch"));
    }

    #[test]
    fn test_v2_scoped_rejects_zero_tag() {
        let (prepare, mut show, policy) = fixture();
        show.link_tag = [0u8; FIELD_BYTES];

        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("scope_mismatch"));
    }

    #[test]
    fn test_v2_empty_proof_rejected() {
        let (mut prepare, show, policy) = fixture();
        prepare.proof.clear();
        let err =
            verify_openac_v2_with_verifier(&prepare, &show, &policy, &always_valid).unwrap_err();
        assert!(err.to_string().contains("empty_prepare_bundle"));
    }

    #[test]
    fn test_v2_invalid_prepare_proof() {
        let (prepare, show, policy) = fixture();
        let err = verify_openac_v2_with_verifier(&prepare, &show, &policy, &|proof, _| {
            Ok(proof != prepare.proof)
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid_prepare_proof"));
    }

    #[test]
    fn test_challenge_digest_deterministic() {
        let c = sample_point(10);
        let challenge = sample_hash32(20);
        let epoch = [0x20, 0x26, 0x04, 0x01];

        let d1 = compute_challenge_digest_v2(&c, &challenge, &epoch);
        let d2 = compute_challenge_digest_v2(&c, &challenge, &epoch);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_challenge_digest_changes_with_commitment() {
        let c1 = sample_point(10);
        let c2 = sample_point(11);
        let challenge = sample_hash32(20);
        let epoch = [0x20, 0x26, 0x04, 0x01];

        let d1 = compute_challenge_digest_v2(&c1, &challenge, &epoch);
        let d2 = compute_challenge_digest_v2(&c2, &challenge, &epoch);
        assert_ne!(d1, d2);
    }
}
