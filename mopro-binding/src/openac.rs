use crate::MoproError;
use sha2::{Digest, Sha256};

pub const HASH_BYTES: usize = 32;
const PREPARE_DOMAIN: &[u8] = b"openac.preparev1";
const SHOW_DOMAIN: &[u8] = b"openac.show.v1";
const SCOPE_DOMAIN: &[u8] = b"openac.scope.v1";
const FIELD_BYTES: usize = 32;
const PREPARE_PUBLIC_INPUT_COUNT: usize = HASH_BYTES;
const SHOW_PUBLIC_INPUT_COUNT: usize = 1 + HASH_BYTES + 4 + HASH_BYTES + HASH_BYTES + HASH_BYTES;

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
    pub expected_challenge: [u8; HASH_BYTES],
    pub prepare_vk_hash: [u8; HASH_BYTES],
    pub show_vk_hash: [u8; HASH_BYTES],
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

fn hash_bytes(input: &[u8]) -> [u8; HASH_BYTES] {
    sha256_concat(&[input])
}

fn append_field_u8(encoded: &mut Vec<u8>, value: u8) {
    let mut field = [0u8; FIELD_BYTES];
    field[FIELD_BYTES - 1] = value;
    encoded.extend_from_slice(&field);
}

fn append_field_bool(encoded: &mut Vec<u8>, value: bool) {
    append_field_u8(encoded, if value { 1 } else { 0 });
}

fn append_field_u8_array<const N: usize>(encoded: &mut Vec<u8>, values: &[u8; N]) {
    values.iter().for_each(|v| append_field_u8(encoded, *v));
}

fn encode_prepare_public_inputs(prepare_commitment: [u8; HASH_BYTES]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PREPARE_PUBLIC_INPUT_COUNT * FIELD_BYTES);
    append_field_u8_array(&mut encoded, &prepare_commitment);
    encoded
}

fn encode_show_public_inputs(
    link_mode: bool,
    link_scope: [u8; HASH_BYTES],
    epoch: [u8; 4],
    prepare_commitment: [u8; HASH_BYTES],
    challenge_digest: [u8; HASH_BYTES],
    link_tag: [u8; HASH_BYTES],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(SHOW_PUBLIC_INPUT_COUNT * FIELD_BYTES);
    append_field_bool(&mut encoded, link_mode);
    append_field_u8_array(&mut encoded, &link_scope);
    append_field_u8_array(&mut encoded, &epoch);
    append_field_u8_array(&mut encoded, &prepare_commitment);
    append_field_u8_array(&mut encoded, &challenge_digest);
    append_field_u8_array(&mut encoded, &link_tag);
    encoded
}

fn verify_public_input_prefix(
    proof: &[u8],
    expected_public_inputs: &[u8],
    missing_code: &str,
    mismatch_code: &str,
) -> Result<(), MoproError> {
    if proof.len() < expected_public_inputs.len() {
        return Err(verification_error(missing_code));
    }

    if proof[..expected_public_inputs.len()] != expected_public_inputs[..] {
        return Err(verification_error(mismatch_code));
    }

    Ok(())
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
    let trusted_prepare_vk_hash = hash_bytes(&prepare.vk);
    if trusted_prepare_vk_hash != policy.prepare_vk_hash {
        return Err(verification_error("untrusted_prepare_vk"));
    }

    let trusted_show_vk_hash = hash_bytes(&show.vk);
    if trusted_show_vk_hash != policy.show_vk_hash {
        return Err(verification_error("untrusted_show_vk"));
    }

    verify_noir_bundle_with(
        &prepare.proof,
        &prepare.vk,
        "invalid_prepare_proof",
        verifier,
    )?;
    verify_noir_bundle_with(&show.proof, &show.vk, "invalid_show_proof", verifier)?;

    let expected_prepare_public_inputs = encode_prepare_public_inputs(prepare.prepare_commitment);
    verify_public_input_prefix(
        &prepare.proof,
        &expected_prepare_public_inputs,
        "prepare_public_inputs_missing",
        "prepare_public_inputs_mismatch",
    )?;

    let public_link_scope = match policy.link_mode {
        OpenAcLinkMode::Unlinkable => [0u8; HASH_BYTES],
        OpenAcLinkMode::ScopedLinkable => policy
            .link_scope
            .ok_or_else(|| verification_error("scope_mismatch"))?,
    };

    let expected_show_public_inputs = encode_show_public_inputs(
        matches!(policy.link_mode, OpenAcLinkMode::ScopedLinkable),
        public_link_scope,
        policy.epoch,
        show.prepare_commitment,
        show.challenge_digest,
        show.link_tag,
    );
    verify_public_input_prefix(
        &show.proof,
        &expected_show_public_inputs,
        "show_public_inputs_missing",
        "show_public_inputs_mismatch",
    )?;

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

    if show.challenge != policy.expected_challenge {
        return Err(verification_error("invalid_challenge"));
    }

    let expected_challenge_digest = compute_challenge_digest(
        policy.expected_challenge,
        show.prepare_commitment,
        policy.epoch,
    );
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

    fn combine_with_public_inputs(public_inputs: Vec<u8>, proof_body: &[u8]) -> Vec<u8> {
        let mut out = public_inputs;
        out.extend_from_slice(proof_body);
        out
    }

    fn proof_body_from_combined(proof: &[u8], num_public_inputs: usize) -> Vec<u8> {
        let offset = num_public_inputs * FIELD_BYTES;
        proof[offset..].to_vec()
    }

    fn rewrite_show_proof_public_inputs(show: &mut OpenAcShowPresentation, policy: &OpenAcPolicy) {
        let link_scope = match policy.link_mode {
            OpenAcLinkMode::Unlinkable => [0u8; HASH_BYTES],
            OpenAcLinkMode::ScopedLinkable => policy.link_scope.unwrap_or([0u8; HASH_BYTES]),
        };
        let show_public_inputs = encode_show_public_inputs(
            matches!(policy.link_mode, OpenAcLinkMode::ScopedLinkable),
            link_scope,
            policy.epoch,
            show.prepare_commitment,
            show.challenge_digest,
            show.link_tag,
        );
        let proof_body = proof_body_from_combined(&show.proof, SHOW_PUBLIC_INPUT_COUNT);
        show.proof = combine_with_public_inputs(show_public_inputs, &proof_body);
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
        let prepare_vk = vec![4, 5, 6];
        let show_vk = vec![10, 11, 12];
        let prepare_public_inputs = encode_prepare_public_inputs(prepare_commitment);
        let show_public_inputs = encode_show_public_inputs(
            true,
            link_scope,
            epoch,
            prepare_commitment,
            challenge_digest,
            link_tag,
        );

        let prepare = OpenAcPrepareArtifact {
            created_at_unix: 100,
            expires_at_unix: 200,
            sod_hash,
            mrz_hash,
            prepare_commitment,
            proof: combine_with_public_inputs(prepare_public_inputs, &[1, 2, 3]),
            vk: prepare_vk.clone(),
        };

        let show = OpenAcShowPresentation {
            sod_hash,
            mrz_hash,
            prepare_commitment,
            challenge,
            challenge_digest,
            link_tag,
            proof: combine_with_public_inputs(show_public_inputs, &[7, 8, 9]),
            vk: show_vk.clone(),
        };

        let policy = OpenAcPolicy {
            link_mode: OpenAcLinkMode::ScopedLinkable,
            link_scope: Some(link_scope),
            epoch,
            now_unix: 150,
            expected_challenge: challenge,
            prepare_vk_hash: hash_bytes(&prepare_vk),
            show_vk_hash: hash_bytes(&show_vk),
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
        rewrite_show_proof_public_inputs(&mut show, &policy);

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
        let (prepare, mut show, mut policy) = scoped_fixture();
        policy.link_scope = Some(sample_hash(99));
        rewrite_show_proof_public_inputs(&mut show, &policy);

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
                Ok(proof != prepare.proof)
            })
            .unwrap_err();
        assert!(err.to_string().contains("invalid_prepare_proof"));
    }

    #[test]
    fn test_fails_when_show_proof_invalid() {
        let (prepare, show, policy) = scoped_fixture();
        let err =
            verify_openac_prepare_show_with_verifier(&prepare, &show, &policy, &|proof, _vk| {
                Ok(proof != show.proof)
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
    fn test_fails_when_challenge_not_from_verifier_policy() {
        let (prepare, mut show, policy) = scoped_fixture();
        show.challenge = sample_hash(200);
        show.challenge_digest =
            compute_challenge_digest(show.challenge, show.prepare_commitment, policy.epoch);
        rewrite_show_proof_public_inputs(&mut show, &policy);

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid_challenge"));
    }

    #[test]
    fn test_fails_when_prepare_vk_is_not_trusted() {
        let (prepare, show, mut policy) = scoped_fixture();
        policy.prepare_vk_hash = sample_hash(99);

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("untrusted_prepare_vk"));
    }

    #[test]
    fn test_fails_when_show_public_inputs_do_not_match_presentation() {
        let (prepare, mut show, policy) = scoped_fixture();
        show.proof[0] ^= 0x01;

        let err = verify_openac_prepare_show_with_verifier(
            &prepare,
            &show,
            &policy,
            &always_valid_verifier,
        )
        .unwrap_err();
        assert!(err.to_string().contains("show_public_inputs_mismatch"));
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
