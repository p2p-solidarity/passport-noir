//! OpenAC v3 (Path A): Pedersen commitment with in-circuit device binding.
//!
//! Upgrades from v2 (arity-4 Pedersen) to v3 (arity-5), folding an enclave
//! public-key digest `pk_digest` into the commitment so the show circuit can
//! enforce in-circuit ECDSA-P256 device binding without a separate
//! device-binding proof.
//!
//! Noir reference:
//!   * `openac_core::commit::commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, r)`
//!   * `openac_core::device::verify_device_binding(pk_x, pk_y, sig, nonce_hash)`
//!   * `openac_core::show::compute_challenge_digest` — domain `openac.show.v2`
//!     (show-phase SHA256 digest math is unchanged from v2; only the
//!     commitment pre-image differs).
//!
//! Breaking change from v2:
//!   * `PrepareArtifactV3::pk_digest` is a new field — old v2 artifacts
//!     cannot be upgraded in place, must be re-issued (see
//!     `spec/x509-migration.md §3`).

use crate::MoproError;
use sha2::{Digest, Sha256};

pub const FIELD_BYTES: usize = 32;

// Credential-type domain separators. Authoritative values live in
// `circuits/openac_core/src/commit.nr`. v3 introduced `DOMAIN_X509 = 0x02`,
// shifting SDJWT / MDL by one vs. v2. Keep the v3 layout here; v2 callers
// must continue to use `openac_v2::DOMAIN_*`.
pub const DOMAIN_PASSPORT: u8 = 0x01;
pub const DOMAIN_X509: u8 = 0x02;
pub const DOMAIN_SDJWT: u8 = 0x03;
pub const DOMAIN_MDL: u8 = 0x04;

// Show-phase digest domain. Kept at v2 because the SHA256 digest math did not
// change in v3 Path A — only the Pedersen commitment's pre-image did.
const SHOW_DOMAIN_V2: &[u8] = b"openac.show.v2";

use crate::openac_v2::{LinkMode, PedersenPoint};

/// Prepare artifact with Pedersen commitment + enclave pk_digest (v3 Path A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareArtifactV3 {
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    /// Credential-type domain (passport / x509 / sdjwt / mdl).
    pub credential_type: u8,
    /// Pedersen commitment C = commit_attributes_v3(ctype, hi, lo, pk_digest, r).
    pub commitment: PedersenPoint,
    /// Enclave public-key digest bound inside the commitment.
    /// Field element serialized big-endian in 32 bytes.
    pub pk_digest: [u8; FIELD_BYTES],
    /// Blinding randomness (needed for re-randomization).
    pub link_rand: [u8; FIELD_BYTES],
    /// Noir proof bytes (prepare circuit).
    pub proof: Vec<u8>,
    /// Verification key bytes (prepare circuit).
    pub vk: Vec<u8>,
}

/// Show presentation with in-circuit ECDSA device binding (v3 Path A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowPresentationV3 {
    /// Pedersen commitment point (MUST match prepare's commitment).
    pub commitment: PedersenPoint,
    /// Enclave pk_digest — MUST match the value bound during prepare.
    pub pk_digest: [u8; FIELD_BYTES],
    /// Verifier-supplied nonce signed by the enclave (public input to show).
    pub nonce_hash: [u8; 32],
    /// Challenge from verifier (raw bytes, folded into challenge_digest).
    pub challenge: [u8; 32],
    /// SHA256 challenge digest: SHA256("openac.show.v2" || cx || cy || challenge || epoch).
    pub challenge_digest: [u8; 32],
    /// Scoped link tag (Field, 0 for unlinkable mode).
    pub link_tag: [u8; FIELD_BYTES],
    /// Noir proof bytes (show circuit).
    pub proof: Vec<u8>,
    /// Verification key bytes (show circuit).
    pub vk: Vec<u8>,
}

/// Verification policy (v3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyV3 {
    pub link_mode: LinkMode,
    /// Scope identifier (None for unlinkable mode).
    pub link_scope: Option<[u8; FIELD_BYTES]>,
    pub epoch: [u8; 4],
    pub epoch_field: [u8; FIELD_BYTES],
    pub now_unix: u64,
    pub expected_challenge: [u8; 32],
    /// Nonce the verifier issued and expects the enclave to sign.
    pub expected_nonce_hash: [u8; 32],
    pub prepare_vk_hash: [u8; 32],
    pub show_vk_hash: [u8; 32],
}

fn verification_error(code: &str) -> MoproError {
    MoproError::VerificationError(code.to_string())
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Search for a 32-byte target as a Field-aligned public input in the proof
/// byte prefix (UltraHonk serializes public inputs first, as 32-byte BE fields).
fn proof_contains_field(proof: &[u8], target: &[u8; FIELD_BYTES]) -> bool {
    if proof.len() < FIELD_BYTES {
        return false;
    }
    let search_limit = proof.len().saturating_sub(FIELD_BYTES);
    for offset in (0..=search_limit).step_by(FIELD_BYTES) {
        if &proof[offset..offset + FIELD_BYTES] == &target[..] {
            return true;
        }
    }
    false
}

fn verify_commitment_in_proof(
    proof: &[u8],
    commitment: &PedersenPoint,
    error_code: &str,
) -> Result<(), MoproError> {
    if proof.len() < FIELD_BYTES * 2 {
        return Err(verification_error(error_code));
    }

    let target = [&commitment.x[..], &commitment.y[..]].concat();
    let search_limit = proof.len().saturating_sub(FIELD_BYTES * 2);
    for offset in (0..=search_limit).step_by(FIELD_BYTES) {
        if proof[offset..offset + FIELD_BYTES * 2] == target[..] {
            return Ok(());
        }
    }
    Err(verification_error(error_code))
}

/// Compute challenge digest (v3 uses the same SHA256 math as v2).
/// SHA256("openac.show.v2" || commitment_x || commitment_y || challenge || epoch)
pub fn compute_challenge_digest_v3(
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

/// Verify a linked v3 prepare + show pair (Path A: in-circuit device binding).
pub fn verify_openac_v3(
    prepare: &PrepareArtifactV3,
    show: &ShowPresentationV3,
    policy: &PolicyV3,
) -> Result<(), MoproError> {
    verify_openac_v3_with_verifier(prepare, show, policy, &crate::noir::verify_noir_proof)
}

pub fn verify_openac_v3_with_verifier<F>(
    prepare: &PrepareArtifactV3,
    show: &ShowPresentationV3,
    policy: &PolicyV3,
    verifier: &F,
) -> Result<(), MoproError>
where
    F: Fn(Vec<u8>, Vec<u8>) -> Result<bool, MoproError>,
{
    // 1. VK trust check
    if sha256_hash(&prepare.vk) != policy.prepare_vk_hash {
        return Err(verification_error("untrusted_prepare_vk"));
    }
    if sha256_hash(&show.vk) != policy.show_vk_hash {
        return Err(verification_error("untrusted_show_vk"));
    }

    // 2. Noir proofs
    if prepare.proof.is_empty() || prepare.vk.is_empty() {
        return Err(verification_error("empty_prepare_bundle"));
    }
    if !verifier(prepare.proof.clone(), prepare.vk.clone())? {
        return Err(verification_error("invalid_prepare_proof"));
    }

    if show.proof.is_empty() || show.vk.is_empty() {
        return Err(verification_error("empty_show_bundle"));
    }
    if !verifier(show.proof.clone(), show.vk.clone())? {
        return Err(verification_error("invalid_show_proof"));
    }

    // 3. TTL
    if prepare.created_at_unix > policy.now_unix {
        return Err(verification_error("prepare_not_active"));
    }
    if policy.now_unix > prepare.expires_at_unix {
        return Err(verification_error("expired_prepare"));
    }

    // 4. Commitment coordinates must appear as public inputs in both proofs.
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

    // 5. Prepare / show link via commitment equality (Pedersen point on Grumpkin).
    if prepare.commitment != show.commitment {
        return Err(verification_error("commitment_mismatch"));
    }

    // 6. pk_digest consistency — same enclave bound into commitment for both
    // phases. The pk_digest itself is a Field (32 bytes BE) that the show
    // circuit derives from the enclave pk and asserts equal to the value
    // folded into the v3 commitment. Checking equality here complements the
    // zk proof by rejecting tampered external metadata.
    if prepare.pk_digest != show.pk_digest {
        return Err(verification_error("pk_digest_mismatch"));
    }

    // The show circuit exposes nonce_hash as a public input (Path A). Verify
    // the byte value appears in the show proof so a caller cannot decouple
    // their stated nonce_hash from the actual signed message.
    if !proof_contains_field(&show.proof, &show.nonce_hash) {
        return Err(verification_error("nonce_hash_not_in_proof"));
    }

    // 7. Challenge binding
    if show.challenge != policy.expected_challenge {
        return Err(verification_error("invalid_challenge"));
    }
    if show.nonce_hash != policy.expected_nonce_hash {
        return Err(verification_error("invalid_nonce_hash"));
    }
    let expected_digest =
        compute_challenge_digest_v3(&show.commitment, &policy.expected_challenge, &policy.epoch);
    if show.challenge_digest != expected_digest {
        return Err(verification_error("invalid_challenge_digest"));
    }

    // 8. Scope / linkability
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

    /// Proof prefix layout: commitment(x,y), pk_digest, nonce_hash, then a suffix.
    fn mock_show_proof(
        commitment: &PedersenPoint,
        pk_digest: &[u8; FIELD_BYTES],
        nonce_hash: &[u8; 32],
        suffix: &[u8],
    ) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(&commitment.x);
        proof.extend_from_slice(&commitment.y);
        proof.extend_from_slice(pk_digest);
        proof.extend_from_slice(nonce_hash);
        proof.extend_from_slice(suffix);
        proof
    }

    fn mock_prepare_proof(commitment: &PedersenPoint, suffix: &[u8]) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(&commitment.x);
        proof.extend_from_slice(&commitment.y);
        proof.extend_from_slice(suffix);
        proof
    }

    fn fixture() -> (PrepareArtifactV3, ShowPresentationV3, PolicyV3) {
        let commitment = sample_point(10);
        let pk_digest = sample_field(60);
        let nonce_hash = sample_hash32(70);
        let challenge = sample_hash32(44);
        let epoch = [0x20, 0x26, 0x04, 0x01];
        let challenge_digest = compute_challenge_digest_v3(&commitment, &challenge, &epoch);
        let scope = sample_field(55);
        let link_tag = sample_field(77);

        let prepare_vk = vec![1, 2, 3];
        let show_vk = vec![4, 5, 6];

        let prepare = PrepareArtifactV3 {
            created_at_unix: 100,
            expires_at_unix: 200,
            credential_type: DOMAIN_PASSPORT,
            commitment,
            pk_digest,
            link_rand: sample_field(33),
            proof: mock_prepare_proof(&commitment, &[10, 20, 30]),
            vk: prepare_vk.clone(),
        };

        let show = ShowPresentationV3 {
            commitment,
            pk_digest,
            nonce_hash,
            challenge,
            challenge_digest,
            link_tag,
            proof: mock_show_proof(&commitment, &pk_digest, &nonce_hash, &[40, 50, 60]),
            vk: show_vk.clone(),
        };

        let policy = PolicyV3 {
            link_mode: LinkMode::ScopedLinkable,
            link_scope: Some(scope),
            epoch,
            epoch_field: sample_field(0x20),
            now_unix: 150,
            expected_challenge: challenge,
            expected_nonce_hash: nonce_hash,
            prepare_vk_hash: sha256_hash(&prepare_vk),
            show_vk_hash: sha256_hash(&show_vk),
        };

        (prepare, show, policy)
    }

    #[test]
    fn test_v3_happy_path() {
        let (prepare, show, policy) = fixture();
        verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect("v3 happy path should verify");
    }

    #[test]
    fn test_v3_commitment_mismatch() {
        let (prepare, mut show, policy) = fixture();
        let mut tampered = show.commitment;
        tampered.x[0] ^= 0x01;
        show.commitment = tampered;
        show.proof = mock_show_proof(&tampered, &show.pk_digest, &show.nonce_hash, &[40, 50, 60]);
        show.challenge_digest =
            compute_challenge_digest_v3(&tampered, &policy.expected_challenge, &policy.epoch);

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("commitment_mismatch"));
    }

    #[test]
    fn test_v3_pk_digest_mismatch_rejected() {
        let (prepare, mut show, policy) = fixture();
        show.pk_digest[0] ^= 0x01;
        // Rebuild show proof with new pk_digest so binding check passes
        show.proof = mock_show_proof(
            &show.commitment,
            &show.pk_digest,
            &show.nonce_hash,
            &[40, 50, 60],
        );
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("pk_digest_mismatch"));
    }

    #[test]
    fn test_v3_nonce_hash_missing_from_proof_rejected() {
        let (prepare, mut show, policy) = fixture();
        // Strip nonce_hash from proof by rebuilding without it.
        let mut stripped = Vec::new();
        stripped.extend_from_slice(&show.commitment.x);
        stripped.extend_from_slice(&show.commitment.y);
        stripped.extend_from_slice(&show.pk_digest);
        // Note: no nonce_hash
        stripped.extend_from_slice(&[40, 50, 60]);
        show.proof = stripped;

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("nonce_hash_not_in_proof"));
    }

    #[test]
    fn test_v3_wrong_nonce_hash_rejected() {
        let (prepare, show, mut policy) = fixture();
        policy.expected_nonce_hash[0] ^= 0x5A;
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("invalid_nonce_hash"));
    }

    #[test]
    fn test_v3_expired_prepare() {
        let (prepare, show, mut policy) = fixture();
        policy.now_unix = 300;
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("expired_prepare"));
    }

    #[test]
    fn test_v3_wrong_challenge() {
        let (prepare, mut show, policy) = fixture();
        show.challenge[0] ^= 0xFF;
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("invalid_challenge"));
    }

    #[test]
    fn test_v3_untrusted_vk() {
        let (prepare, show, mut policy) = fixture();
        policy.prepare_vk_hash = sample_hash32(99);
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("untrusted_prepare_vk"));
    }

    #[test]
    fn test_v3_unlinkable_mode() {
        let (prepare, mut show, mut policy) = fixture();
        policy.link_mode = LinkMode::Unlinkable;
        policy.link_scope = None;
        show.link_tag = [0u8; FIELD_BYTES];
        show.challenge_digest = compute_challenge_digest_v3(
            &show.commitment,
            &policy.expected_challenge,
            &policy.epoch,
        );
        verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect("unlinkable mode should verify");
    }

    #[test]
    fn test_v3_unlinkable_rejects_nonzero_tag() {
        let (prepare, show, mut policy) = fixture();
        policy.link_mode = LinkMode::Unlinkable;
        policy.link_scope = None;
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("scope_mismatch"));
    }

    #[test]
    fn test_v3_scoped_rejects_zero_tag() {
        let (prepare, mut show, policy) = fixture();
        show.link_tag = [0u8; FIELD_BYTES];
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("scope_mismatch"));
    }

    #[test]
    fn test_v3_empty_proof_rejected() {
        let (mut prepare, show, policy) = fixture();
        prepare.proof.clear();
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        assert!(err.to_string().contains("empty_prepare_bundle"));
    }

    #[test]
    fn test_v3_invalid_prepare_proof() {
        let (prepare, show, policy) = fixture();
        let prepare_bytes = prepare.proof.clone();
        let err =
            verify_openac_v3_with_verifier(&prepare, &show, &policy, &|proof: Vec<u8>, _| {
                Ok(proof != prepare_bytes)
            })
            .expect_err("must reject");
        assert!(err.to_string().contains("invalid_prepare_proof"));
    }

    #[test]
    fn test_challenge_digest_v3_deterministic() {
        let c = sample_point(10);
        let challenge = sample_hash32(20);
        let epoch = [0x20, 0x26, 0x04, 0x01];
        let d1 = compute_challenge_digest_v3(&c, &challenge, &epoch);
        let d2 = compute_challenge_digest_v3(&c, &challenge, &epoch);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_challenge_digest_v3_matches_v2_math() {
        // v3 Path A kept the show-phase domain at "openac.show.v2" because the
        // SHA256 digest math is unchanged. Cross-check to catch accidental
        // drift.
        let c = sample_point(42);
        let challenge = sample_hash32(99);
        let epoch = [0x01, 0x02, 0x03, 0x04];
        let d3 = compute_challenge_digest_v3(&c, &challenge, &epoch);
        let d2 = crate::openac_v2::compute_challenge_digest_v2(&c, &challenge, &epoch);
        assert_eq!(d3, d2, "v3 digest must match v2 (shared domain/math)");
    }
}
