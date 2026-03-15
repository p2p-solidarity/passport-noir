use crate::MoproError;
use sha2::{Digest, Sha256};

pub const HASH_BYTES: usize = 32;
const PREPARE_DOMAIN: &[u8] = b"openac.preparev1";
const SHOW_DOMAIN: &[u8] = b"openac.show.v1";
const SCOPE_DOMAIN: &[u8] = b"openac.scope.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAcLinkMode {
    Unlinkable,
    ScopedLinkable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAcPrepareArtifact {
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub sod_hash: [u8; HASH_BYTES],
    pub mrz_hash: [u8; HASH_BYTES],
    pub prepare_commitment: [u8; HASH_BYTES],
    pub proof: Vec<u8>,
    pub vk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAcShowPresentation {
    pub sod_hash: [u8; HASH_BYTES],
    pub mrz_hash: [u8; HASH_BYTES],
    pub prepare_commitment: [u8; HASH_BYTES],
    pub challenge: [u8; HASH_BYTES],
    pub challenge_digest: [u8; HASH_BYTES],
    pub link_tag: [u8; HASH_BYTES],
    pub proof: Vec<u8>,
    pub vk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAcPolicy {
    pub link_mode: OpenAcLinkMode,
    pub link_scope: Option<[u8; HASH_BYTES]>,
    pub epoch: [u8; 4],
    pub now_unix: u64,
}

fn verification_error(code: &str) -> MoproError {
    MoproError::VerificationError(code.to_string())
}

fn verify_noir_bundle_with<F>(
    proof: &[u8],
    vk: &[u8],
    invalid_code: &str,
    verifier: &F,
) -> Result<(), MoproError>
where
    F: Fn(Vec<u8>, Vec<u8>) -> Result<bool, MoproError>,
{
    if proof.is_empty() || vk.is_empty() {
        return Err(verification_error("empty_proof_bundle"));
    }

    let is_valid = verifier(proof.to_vec(), vk.to_vec())?;
    if !is_valid {
        return Err(verification_error(invalid_code));
    }

    Ok(())
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; HASH_BYTES] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn compute_prepare_commitment(
    sod_hash: [u8; HASH_BYTES],
    mrz_hash: [u8; HASH_BYTES],
    link_rand: [u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    sha256_concat(&[PREPARE_DOMAIN, &sod_hash, &mrz_hash, &link_rand])
}

pub fn compute_challenge_digest(
    challenge: [u8; HASH_BYTES],
    prepare_commitment: [u8; HASH_BYTES],
    epoch: [u8; 4],
) -> [u8; HASH_BYTES] {
    sha256_concat(&[SHOW_DOMAIN, &challenge, &prepare_commitment, &epoch])
}

pub fn compute_scoped_link_tag(
    prepare_commitment: [u8; HASH_BYTES],
    link_scope: [u8; HASH_BYTES],
    epoch: [u8; 4],
) -> [u8; HASH_BYTES] {
    sha256_concat(&[SCOPE_DOMAIN, &prepare_commitment, &link_scope, &epoch])
}

pub fn verify_openac_prepare_show(
    prepare: &OpenAcPrepareArtifact,
    show: &OpenAcShowPresentation,
    policy: &OpenAcPolicy,
) -> Result<(), MoproError> {
    verify_openac_prepare_show_with_verifier(prepare, show, policy, &crate::noir::verify_noir_proof)
}

pub fn verify_openac_prepare_show_with_verifier<F>(
    prepare: &OpenAcPrepareArtifact,
    show: &OpenAcShowPresentation,
    policy: &OpenAcPolicy,
    verifier: &F,
) -> Result<(), MoproError>
where
    F: Fn(Vec<u8>, Vec<u8>) -> Result<bool, MoproError>,
{
    verify_noir_bundle_with(
        &prepare.proof,
        &prepare.vk,
        "invalid_prepare_proof",
        verifier,
    )?;
    verify_noir_bundle_with(&show.proof, &show.vk, "invalid_show_proof", verifier)?;

    if prepare.created_at_unix > policy.now_unix {
        return Err(verification_error("prepare_not_active"));
    }

    if policy.now_unix > prepare.expires_at_unix {
        return Err(verification_error("expired_prepare"));
    }

    if show.prepare_commitment != prepare.prepare_commitment {
        return Err(verification_error("link_mismatch"));
    }

    if show.sod_hash != prepare.sod_hash {
        return Err(verification_error("sod_hash_mismatch"));
    }

    if show.mrz_hash != prepare.mrz_hash {
        return Err(verification_error("mrz_hash_mismatch"));
    }

    let expected_challenge_digest =
        compute_challenge_digest(show.challenge, show.prepare_commitment, policy.epoch);
    if show.challenge_digest != expected_challenge_digest {
        return Err(verification_error("invalid_challenge"));
    }

    match policy.link_mode {
        OpenAcLinkMode::Unlinkable => {
            if policy.link_scope.is_some() {
                return Err(verification_error("scope_mismatch"));
            }
            if show.link_tag != [0u8; HASH_BYTES] {
                return Err(verification_error("scope_mismatch"));
            }
        }
        OpenAcLinkMode::ScopedLinkable => {
            let scope = policy
                .link_scope
                .ok_or_else(|| verification_error("scope_mismatch"))?;
            let expected_tag =
                compute_scoped_link_tag(show.prepare_commitment, scope, policy.epoch);
            if show.link_tag != expected_tag {
                return Err(verification_error("scope_mismatch"));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always_valid_verifier(_: Vec<u8>, _: Vec<u8>) -> Result<bool, MoproError> {
        Ok(true)
    }

    fn sample_hash(seed: u8) -> [u8; HASH_BYTES] {
        let mut out = [0u8; HASH_BYTES];
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        out
    }

    fn scoped_fixture() -> (OpenAcPrepareArtifact, OpenAcShowPresentation, OpenAcPolicy) {
        let sod_hash = sample_hash(11);
        let mrz_hash = sample_hash(22);
        let link_rand = sample_hash(33);
        let prepare_commitment = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
        let challenge = sample_hash(44);
        let epoch = [0x20, 0x26, 0x03, 0x15];
        let link_scope = sample_hash(55);
        let challenge_digest = compute_challenge_digest(challenge, prepare_commitment, epoch);
        let link_tag = compute_scoped_link_tag(prepare_commitment, link_scope, epoch);

        let prepare = OpenAcPrepareArtifact {
            created_at_unix: 100,
            expires_at_unix: 200,
            sod_hash,
            mrz_hash,
            prepare_commitment,
            proof: vec![1, 2, 3],
            vk: vec![4, 5, 6],
        };

        let show = OpenAcShowPresentation {
            sod_hash,
            mrz_hash,
            prepare_commitment,
            challenge,
            challenge_digest,
            link_tag,
            proof: vec![7, 8, 9],
            vk: vec![10, 11, 12],
        };

        let policy = OpenAcPolicy {
            link_mode: OpenAcLinkMode::ScopedLinkable,
            link_scope: Some(link_scope),
            epoch,
            now_unix: 150,
        };

        (prepare, show, policy)
    }

    #[test]
    fn test_prepare_show_linking_happy_path() {
        let (prepare, show, policy) = scoped_fixture();
        let result = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fails_when_prepare_commitment_mismatch() {
        let (prepare, mut show, policy) = scoped_fixture();
        show.prepare_commitment[0] ^= 0x01;

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("link_mismatch"));
    }

    #[test]
    fn test_fails_when_sod_hash_mismatch() {
        let (prepare, mut show, policy) = scoped_fixture();
        show.sod_hash[0] ^= 0x01;

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("sod_hash_mismatch"));
    }

    #[test]
    fn test_fails_when_mrz_hash_mismatch() {
        let (prepare, mut show, policy) = scoped_fixture();
        show.mrz_hash[0] ^= 0x01;

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("mrz_hash_mismatch"));
    }

    #[test]
    fn test_fails_on_scope_policy_mismatch() {
        let (prepare, show, mut policy) = scoped_fixture();
        policy.link_scope = Some(sample_hash(99));

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("scope_mismatch"));
    }

    #[test]
    fn test_fails_when_prepare_proof_invalid() {
        let (prepare, show, policy) = scoped_fixture();
        let err =
            verify_openac_prepare_show_with_verifier(&prepare, &show, &policy, &|proof, _vk| {
                Ok(proof != vec![1, 2, 3])
            })
            .unwrap_err();
        assert!(err.to_string().contains("invalid_prepare_proof"));
    }

    #[test]
    fn test_fails_when_show_proof_invalid() {
        let (prepare, show, policy) = scoped_fixture();
        let err =
            verify_openac_prepare_show_with_verifier(&prepare, &show, &policy, &|proof, _vk| {
                Ok(proof != vec![7, 8, 9])
            })
            .unwrap_err();
        assert!(err.to_string().contains("invalid_show_proof"));
    }

    #[test]
    fn test_fails_when_proof_bundle_empty() {
        let (mut prepare, show, policy) = scoped_fixture();
        prepare.proof.clear();

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty_proof_bundle"));
    }

    #[test]
    fn test_unlinkable_mode_not_linkable_across_sessions() {
        let sod_hash = sample_hash(1);
        let mrz_hash = sample_hash(2);

        let commitment_a = compute_prepare_commitment(sod_hash, mrz_hash, sample_hash(3));
        let commitment_b = compute_prepare_commitment(sod_hash, mrz_hash, sample_hash(4));

        assert_ne!(commitment_a, commitment_b);
    }

    #[test]
    fn test_scoped_mode_linkable_within_same_scope() {
        let prepare_commitment = sample_hash(17);
        let scope = sample_hash(77);
        let epoch = [0x20, 0x26, 0x03, 0x15];

        let tag_a = compute_scoped_link_tag(prepare_commitment, scope, epoch);
        let tag_b = compute_scoped_link_tag(prepare_commitment, scope, epoch);

        assert_eq!(tag_a, tag_b);
    }

    #[test]
    fn test_scoped_mode_not_linkable_across_epoch() {
        let prepare_commitment = sample_hash(18);
        let scope = sample_hash(78);

        let tag_a = compute_scoped_link_tag(prepare_commitment, scope, [0x20, 0x26, 0x03, 0x15]);
        let tag_b = compute_scoped_link_tag(prepare_commitment, scope, [0x20, 0x26, 0x03, 0x16]);

        assert_ne!(tag_a, tag_b);
    }
}
