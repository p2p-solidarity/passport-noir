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

/// Issue P0-1 (2026-04-28): describes where each public input lives in a
/// proof's public-input prefix. Honk-style proofs serialise public inputs as
/// 32-byte big-endian Field elements at the start of the proof bytes; this
/// struct lets the verifier compare each expected value at its EXACT
/// position rather than scanning for "the bytes appear somewhere", which
/// the audit flagged as too permissive (an attacker could fold attacker-
/// chosen values into one public input slot while still seeing the expected
/// bytes appear in another).
///
/// `field_index` values are *0-based indices into the public-input array*
/// (not byte offsets). For a `[u8; 32]` ABI input, the value occupies 32
/// consecutive Field slots, each containing one byte right-aligned in the
/// 32-byte BE encoding. Callers must therefore use the helpers below to
/// build expected bytes for byte-array inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareLayoutV3 {
    /// Total number of public-input field elements. Used to bound the
    /// proof prefix slice that gets compared.
    pub num_public_inputs: usize,
    /// Index of `out_commitment_x` (Field) within the public input array.
    pub commitment_x_index: usize,
    /// Index of `out_commitment_y` (Field) within the public input array.
    pub commitment_y_index: usize,
    /// Optional indices for additional trust anchors that adapter-specific
    /// policies want to pin (P0-2). For passport_adapter v3.1: csca_root,
    /// dsc_smt_root, exponent. For jwt_x5c_adapter v3.1: smt_root,
    /// jwt_payload_b64h, jwt_signed_hash, issuer_modulus, issuer_format_tag.
    /// Each entry is `(field_index, expected_field_bytes_be32)`.
    pub extra_pinned_fields: Vec<(usize, [u8; FIELD_BYTES])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowLayoutV3 {
    pub num_public_inputs: usize,
    /// Field index of `out_commitment_x`.
    pub commitment_x_index: usize,
    /// Field index of `out_commitment_y`.
    pub commitment_y_index: usize,
    /// Field index where the first byte of `nonce_hash` (Field index of
    /// nonce_hash[0]) sits. Each subsequent byte occupies the next slot.
    pub nonce_hash_first_byte_index: Option<usize>,
    /// Optional adapter-specific pins: link tag, challenge digest, link
    /// scope, epoch, etc.
    pub extra_pinned_fields: Vec<(usize, [u8; FIELD_BYTES])>,
}

/// Encode a single byte (0..=255) in the right-most position of a 32-byte
/// big-endian Field representation. Used for `[u8; N]` ABI inputs where
/// each byte occupies its own Field slot in the public-input array.
pub fn byte_as_field(byte: u8) -> [u8; FIELD_BYTES] {
    let mut out = [0u8; FIELD_BYTES];
    out[FIELD_BYTES - 1] = byte;
    out
}

pub fn bool_as_field(value: bool) -> [u8; FIELD_BYTES] {
    byte_as_field(if value { 1 } else { 0 })
}

/// Encode a u32 as a 32-byte BE Field with the value in the low 4 bytes.
pub fn u32_as_field(value: u32) -> [u8; FIELD_BYTES] {
    let mut out = [0u8; FIELD_BYTES];
    out[FIELD_BYTES - 4..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Decode the proof's public-input prefix into a vector of 32-byte fields.
/// Returns the first `num_fields` aligned 32-byte chunks. The Honk proof
/// format places public inputs at the start, so this is the canonical
/// decode for fixed-ABI verifiers.
fn decode_public_input_prefix(
    proof: &[u8],
    num_fields: usize,
) -> Result<Vec<[u8; FIELD_BYTES]>, MoproError> {
    let needed = num_fields * FIELD_BYTES;
    if proof.len() < needed {
        return Err(verification_error("proof_too_short_for_public_inputs"));
    }
    let mut out = Vec::with_capacity(num_fields);
    for i in 0..num_fields {
        let start = i * FIELD_BYTES;
        let mut field = [0u8; FIELD_BYTES];
        field.copy_from_slice(&proof[start..start + FIELD_BYTES]);
        out.push(field);
    }
    Ok(out)
}

/// Compare each (index, expected) pair against the proof's public-input
/// vector. Used by the strict-mode v3 verifier to enforce that:
///   - `out_commitment_x/y` appear at the ABI-known indices (not anywhere
///     in the proof bytes), closing the audit's "scan-based" concern.
///   - Trust-anchor public inputs (csca_root, dsc_smt_root, exponent,
///     issuer_modulus, smt_root, etc.) match the policy's expected values.
fn assert_public_inputs_at(
    public_inputs: &[[u8; FIELD_BYTES]],
    pinned: &[(usize, [u8; FIELD_BYTES])],
    error_code: &str,
) -> Result<(), MoproError> {
    for (idx, expected) in pinned {
        let actual = public_inputs
            .get(*idx)
            .ok_or_else(|| verification_error(error_code))?;
        if actual != expected {
            return Err(verification_error(error_code));
        }
    }
    Ok(())
}

/// Build the 32-byte BE Field encoding for a byte array under the per-byte
/// Noir ABI ([u8; N] becomes N consecutive Field slots, each holding one
/// byte). Returns a Vec of (field_index, expected_field) tuples ready to
/// drop into `extra_pinned_fields`.
pub fn pin_byte_array(base_field_index: usize, bytes: &[u8]) -> Vec<(usize, [u8; FIELD_BYTES])> {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| (base_field_index + i, byte_as_field(*b)))
        .collect()
}

/// Encode an 18-limb RSA-2048 modulus as 18 consecutive 32-byte Field
/// elements (each limb is a u128, encoded BE in the low 16 bytes of the
/// Field). Used by jwt_x5c_adapter / passport_adapter layouts when pinning
/// the issuer modulus.
pub fn pin_rsa_modulus_limbs(
    base_field_index: usize,
    limbs: &[u128; 18],
) -> Vec<(usize, [u8; FIELD_BYTES])> {
    let mut out = Vec::with_capacity(18);
    for (i, limb) in limbs.iter().enumerate() {
        let mut field = [0u8; FIELD_BYTES];
        // u128 occupies 16 bytes; place at the LSB end of the 32-byte BE Field.
        field[FIELD_BYTES - 16..].copy_from_slice(&limb.to_be_bytes());
        out.push((base_field_index + i, field));
    }
    out
}

/// Encode a Noir Field value (already serialized as 32-byte BE) at a
/// specific index. Convenience wrapper to make adapter layouts read clearly
/// at the call site.
pub fn pin_field(field_index: usize, value: [u8; FIELD_BYTES]) -> (usize, [u8; FIELD_BYTES]) {
    (field_index, value)
}

// ============================================================
// Adapter-specific layout builders (Task 3, 2026-04-28)
// ============================================================
//
// The generic PrepareLayoutV3 / ShowLayoutV3 structs let callers wire any
// circuit by hand, but the security-relevant per-adapter pins (csca_root,
// dsc_smt_root, expected_disclosure_root, jwt_payload_b64h, ...) are easy
// to forget. The builders below take the off-chain policy values as
// strongly-typed arguments so callers cannot construct a layout that
// silently skips a critical pin.
//
// Each builder is annotated with the public-input layout it targets,
// derived from `benchmark/spec.toml`. If the spec changes, the builder
// must be updated in lockstep -- the strict verifier will catch any drift
// because the proof's actual public inputs will not match the layout.

/// passport_adapter v3.1 prepare layout. Public inputs (5 total):
///   0: csca_root
///   1: dsc_smt_root
///   2: exponent (must be 65537 -- circuit asserts this internally too)
///   3: out_commitment_x
///   4: out_commitment_y
pub fn prepare_layout_passport(
    csca_root: [u8; FIELD_BYTES],
    dsc_smt_root: [u8; FIELD_BYTES],
) -> PrepareLayoutV3 {
    PrepareLayoutV3 {
        num_public_inputs: 5,
        commitment_x_index: 3,
        commitment_y_index: 4,
        extra_pinned_fields: vec![
            pin_field(0, csca_root),
            pin_field(1, dsc_smt_root),
            pin_field(2, u32_as_field(65537)),
        ],
    }
}

/// sdjwt_adapter v3 prepare layout. Public inputs (101 total):
///   0..32:  jwt_payload_hash bytes
///   32..64: issuer_pk_x bytes
///   64..96: issuer_pk_y bytes
///   96:     out_commitment_x
///   97:     out_commitment_y
///   98:     out_sd_root_hi
///   99:     out_sd_root_lo
///   100:    out_disclosure_root  <-- REQUIRED off-chain policy pin (P0-5)
///
/// `expected_disclosure_root` must be the Pedersen disclosure root the
/// issuer pre-registered for this credential. Without this argument the
/// SD-JWT presentation verifier would lack the off-chain anchor needed to
/// detect prover-chosen disclosure manifests.
pub fn prepare_layout_sdjwt(
    jwt_payload_hash: &[u8; 32],
    issuer_pk_x: &[u8; 32],
    issuer_pk_y: &[u8; 32],
    expected_sd_root_hi: [u8; FIELD_BYTES],
    expected_sd_root_lo: [u8; FIELD_BYTES],
    expected_disclosure_root: [u8; FIELD_BYTES],
) -> PrepareLayoutV3 {
    let mut pins = Vec::new();
    pins.extend(pin_byte_array(0, jwt_payload_hash));
    pins.extend(pin_byte_array(32, issuer_pk_x));
    pins.extend(pin_byte_array(64, issuer_pk_y));
    pins.push(pin_field(98, expected_sd_root_hi));
    pins.push(pin_field(99, expected_sd_root_lo));
    pins.push(pin_field(100, expected_disclosure_root));
    PrepareLayoutV3 {
        num_public_inputs: 101,
        commitment_x_index: 96,
        commitment_y_index: 97,
        extra_pinned_fields: pins,
    }
}

/// jwt_x5c_adapter v3.1 prepare layout. Public inputs (86 total):
///   0..32:  jwt_payload_b64h bytes  <-- off-chain policy pin (P0-4 residual)
///   32..64: jwt_signed_hash bytes   <-- off-chain policy pin (P0-4 residual)
///   64..82: issuer_modulus limbs
///   82:     smt_root
///   83:     issuer_format_tag
///   84:     out_commitment_x
///   85:     out_commitment_y
///
/// `expected_jwt_payload_b64h` and `expected_jwt_signed_hash` are required
/// arguments because the in-circuit binding only proves these values are
/// the SHA256 of the prover-supplied jwt_payload_norm and jwt_signing_input
/// bytes; the verifier policy MUST tie them to a known, off-chain JWT
/// payload (e.g. one returned by an OIDC discovery endpoint) so an attacker
/// cannot present an unrelated valid JWT.
pub fn prepare_layout_jwt_x5c(
    expected_jwt_payload_b64h: &[u8; 32],
    expected_jwt_signed_hash: &[u8; 32],
    issuer_modulus_limbs: &[u128; 18],
    expected_smt_root: [u8; FIELD_BYTES],
    expected_issuer_format_tag: [u8; FIELD_BYTES],
) -> PrepareLayoutV3 {
    let mut pins = Vec::new();
    pins.extend(pin_byte_array(0, expected_jwt_payload_b64h));
    pins.extend(pin_byte_array(32, expected_jwt_signed_hash));
    pins.extend(pin_rsa_modulus_limbs(64, issuer_modulus_limbs));
    pins.push(pin_field(82, expected_smt_root));
    pins.push(pin_field(83, expected_issuer_format_tag));
    PrepareLayoutV3 {
        num_public_inputs: 86,
        commitment_x_index: 84,
        commitment_y_index: 85,
        extra_pinned_fields: pins,
    }
}

/// openac_show v3 (passport-only) layout. Public inputs (85 total):
///   0:      credential_type (must be DOMAIN_PASSPORT)
///   1..33:  nonce_hash bytes
///   33:     link_mode
///   34:     link_scope
///   35..39: epoch bytes
///   39:     epoch_field
///   40:     current_year
///   41:     current_month
///   42:     current_day
///   43:     age_threshold
///   44:     disclose_nationality
///   45:     disclose_age
///   46:     out_commitment_x
///   47:     out_commitment_y
///   48..80: out_challenge_digest bytes
///   80:     out_link_tag
///   81:     out_is_older
///   82..85: out_nationality bytes
pub fn show_layout_openac(
    expected_link_mode: bool,
    expected_link_scope: [u8; FIELD_BYTES],
    expected_epoch: &[u8; 4],
    expected_epoch_field: [u8; FIELD_BYTES],
    expected_challenge_digest: &[u8; 32],
    expected_link_tag: [u8; FIELD_BYTES],
) -> ShowLayoutV3 {
    let mut pins = Vec::new();
    // P1-8: pin credential_type to DOMAIN_PASSPORT.
    pins.push(pin_field(0, byte_as_field(DOMAIN_PASSPORT)));
    pins.push(pin_field(33, bool_as_field(expected_link_mode)));
    pins.push(pin_field(34, expected_link_scope));
    pins.extend(pin_byte_array(35, expected_epoch));
    pins.push(pin_field(39, expected_epoch_field));
    pins.extend(pin_byte_array(48, expected_challenge_digest));
    pins.push(pin_field(80, expected_link_tag));
    ShowLayoutV3 {
        num_public_inputs: 85,
        commitment_x_index: 46,
        commitment_y_index: 47,
        nonce_hash_first_byte_index: Some(1),
        extra_pinned_fields: pins,
    }
}

/// x509_show v3 layout. Public inputs (41 total):
///   0:      in_commitment_x509_x
///   1:      in_commitment_x509_y
///   2..34:  nonce_hash bytes
///   34:     target_domain_hash  <-- REQUIRED off-chain policy pin
///   35:     link_mode
///   36:     link_scope
///   37:     epoch
///   38:     out_link_tag
///   39:     out_domain_match
///   40:     out_challenge_digest
pub fn show_layout_x509(
    expected_target_domain_hash: [u8; FIELD_BYTES],
    expected_link_mode: bool,
    expected_link_scope: [u8; FIELD_BYTES],
    expected_epoch: [u8; FIELD_BYTES],
    expected_link_tag: [u8; FIELD_BYTES],
    expected_challenge_digest: [u8; FIELD_BYTES],
) -> ShowLayoutV3 {
    let mut pins = Vec::new();
    pins.push(pin_field(34, expected_target_domain_hash));
    pins.push(pin_field(35, bool_as_field(expected_link_mode)));
    pins.push(pin_field(36, expected_link_scope));
    pins.push(pin_field(37, expected_epoch));
    pins.push(pin_field(38, expected_link_tag));
    pins.push(pin_field(40, expected_challenge_digest));
    ShowLayoutV3 {
        num_public_inputs: 41,
        commitment_x_index: 0,
        commitment_y_index: 1,
        nonce_hash_first_byte_index: Some(2),
        extra_pinned_fields: pins,
    }
}

/// composite_show v3 layout. Public inputs (49 total):
///   0:      in_commitment_passport_x  <-- pinned via standard commitment_x_index
///   1:      in_commitment_passport_y  <-- pinned via standard commitment_y_index
///   2:      in_commitment_aux_x       <-- pinned via extra_pinned_fields
///   3:      in_commitment_aux_y       <-- pinned via extra_pinned_fields
///   4:      aux_domain
///   5..37:  nonce_hash bytes
///   37:     age_threshold
///   38..41: current_year, month, day
///   41:     target_aux_hash  <-- REQUIRED off-chain policy pin
///   42:     link_mode
///   43:     link_scope
///   44:     epoch
///   45:     out_link_tag
///   46:     out_is_older
///   47:     out_aux_predicate
///   48:     out_challenge_digest
///
/// composite_show binds two commitments: the passport credential (indices
/// 0,1) is the one carried via `ShowPresentationV3.commitment` and gets
/// pinned through the standard `commitment_x/y_index`. The aux credential
/// (indices 2,3) is supplied as a separate `aux_commitment` argument and
/// pinned via `extra_pinned_fields`. Without binding the aux pair, an
/// attacker could swap their X.509 / SD-JWT credential for a different one
/// while keeping the passport bundle visible.
pub fn show_layout_composite(
    aux_commitment: &PedersenPoint,
    aux_domain: [u8; FIELD_BYTES],
    expected_target_aux_hash: [u8; FIELD_BYTES],
    expected_link_mode: bool,
    expected_link_scope: [u8; FIELD_BYTES],
    expected_epoch: [u8; FIELD_BYTES],
    expected_link_tag: [u8; FIELD_BYTES],
    expected_challenge_digest: [u8; FIELD_BYTES],
) -> ShowLayoutV3 {
    let mut pins = Vec::new();
    pins.push(pin_field(2, aux_commitment.x));
    pins.push(pin_field(3, aux_commitment.y));
    pins.push(pin_field(4, aux_domain));
    pins.push(pin_field(41, expected_target_aux_hash));
    pins.push(pin_field(42, bool_as_field(expected_link_mode)));
    pins.push(pin_field(43, expected_link_scope));
    pins.push(pin_field(44, expected_epoch));
    pins.push(pin_field(45, expected_link_tag));
    pins.push(pin_field(48, expected_challenge_digest));
    ShowLayoutV3 {
        num_public_inputs: 49,
        commitment_x_index: 0,
        commitment_y_index: 1,
        nonce_hash_first_byte_index: Some(5),
        extra_pinned_fields: pins,
    }
}

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
///
/// Task 1 follow-up (2026-04-28): `prepare_layout` and `show_layout` are
/// now REQUIRED (no longer Option). The previous "fall back to a 32-byte-
/// aligned scan when missing" path was deleted -- it gave attackers a way
/// to satisfy the verifier with public inputs that just happened to appear
/// somewhere in the proof bytes. Callers MUST construct adapter-specific
/// layouts (see `prepare_layout_passport`, `show_layout_openac`, etc.) so
/// every public input is pinned at its ABI-known field index.
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
    /// Issue P0-1 / P0-2 (2026-04-28): ABI-aware layout for the prepare
    /// proof. The verifier uses it to compare each expected public input
    /// against its precise field index (commitment, csca_root, smt_root,
    /// exponent, issuer_modulus, expected_disclosure_root, ...). Built via
    /// the adapter-specific helpers (e.g. `prepare_layout_passport`).
    pub prepare_layout: PrepareLayoutV3,
    /// Same role for the show proof. Built via `show_layout_openac`,
    /// `show_layout_x509`, or `show_layout_composite`.
    pub show_layout: ShowLayoutV3,
}

fn verification_error(code: &str) -> MoproError {
    MoproError::VerificationError(code.to_string())
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// Removed (Task 1 follow-up, 2026-04-28):
//   * `proof_contains_field` — scanned for a 32-byte value at any
//     32-byte-aligned position. Replaced by the strict layout check below.
//   * `verify_commitment_in_proof` — same scan-based approach for the
//     commitment pair. Replaced by `assert_public_inputs_at` calls keyed on
//     `PolicyV3.{prepare,show}_layout.commitment_x/y_index`.

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

    // 4. Public-input prefix checks. P0-1 / P0-2 (2026-04-28): the
    //    verifier ALWAYS uses ABI-aware comparison. Each expected value is
    //    pinned at its known field index; the legacy "scan for value
    //    anywhere" fallback was removed in the Task 1 follow-up because it
    //    let an attacker satisfy the check with public inputs that just
    //    happened to appear somewhere in the proof bytes.
    let prepare_pis =
        decode_public_input_prefix(&prepare.proof, policy.prepare_layout.num_public_inputs)?;
    assert_public_inputs_at(
        &prepare_pis,
        &[
            (
                policy.prepare_layout.commitment_x_index,
                prepare.commitment.x,
            ),
            (
                policy.prepare_layout.commitment_y_index,
                prepare.commitment.y,
            ),
        ],
        "prepare_commitment_not_in_proof",
    )?;
    assert_public_inputs_at(
        &prepare_pis,
        &policy.prepare_layout.extra_pinned_fields,
        "prepare_public_input_mismatch",
    )?;

    let show_pis = decode_public_input_prefix(&show.proof, policy.show_layout.num_public_inputs)?;
    assert_public_inputs_at(
        &show_pis,
        &[
            (policy.show_layout.commitment_x_index, show.commitment.x),
            (policy.show_layout.commitment_y_index, show.commitment.y),
        ],
        "show_commitment_not_in_proof",
    )?;
    if let Some(base) = policy.show_layout.nonce_hash_first_byte_index {
        let nonce_pins = pin_byte_array(base, &show.nonce_hash);
        assert_public_inputs_at(&show_pis, &nonce_pins, "nonce_hash_not_in_proof")?;
    }
    assert_public_inputs_at(
        &show_pis,
        &policy.show_layout.extra_pinned_fields,
        "show_public_input_mismatch",
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

    // (Task 1 follow-up: the legacy `proof_contains_field` scan for
    // nonce_hash was deleted; the layout-driven check above already pins
    // every nonce byte at its ABI-known index when
    // `show_layout.nonce_hash_first_byte_index` is set.)

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

    /// Synthetic strict-layout test proof builder. Layout:
    ///   field 0: commitment.x
    ///   field 1: commitment.y
    ///   field 2: pk_digest
    ///   field 3..35: nonce_hash bytes (one Noir [u8; N] slot per byte, BE)
    ///   suffix: opaque proof bytes
    /// Total public inputs = 35 fields.
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
        for b in nonce_hash {
            proof.extend_from_slice(&byte_as_field(*b));
        }
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

    fn fixture_layouts() -> (PrepareLayoutV3, ShowLayoutV3) {
        // Synthetic prepare layout: just the 2 commitment fields.
        let prepare_layout = PrepareLayoutV3 {
            num_public_inputs: 2,
            commitment_x_index: 0,
            commitment_y_index: 1,
            extra_pinned_fields: Vec::new(),
        };
        // Synthetic show layout: commitment.x, commitment.y, pk_digest,
        // then nonce_hash bytes spread across 32 Field slots (Noir's
        // canonical [u8; 32] ABI encoding).
        let show_layout = ShowLayoutV3 {
            num_public_inputs: 35,
            commitment_x_index: 0,
            commitment_y_index: 1,
            nonce_hash_first_byte_index: Some(3),
            extra_pinned_fields: Vec::new(),
        };
        (prepare_layout, show_layout)
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

        let (prepare_layout, show_layout) = fixture_layouts();
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
            prepare_layout,
            show_layout,
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
        // Strip nonce_hash bytes from proof by rebuilding without them.
        // The strict layout still expects 35 public input fields, so a
        // proof that lacks the trailing nonce slots is rejected first as
        // "proof_too_short_for_public_inputs" (fail-closed).
        let mut stripped = Vec::new();
        stripped.extend_from_slice(&show.commitment.x);
        stripped.extend_from_slice(&show.commitment.y);
        stripped.extend_from_slice(&show.pk_digest);
        // Note: no nonce_hash
        stripped.extend_from_slice(&[40, 50, 60]);
        show.proof = stripped;

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("proof_too_short_for_public_inputs")
                || msg.contains("nonce_hash_not_in_proof"),
            "unexpected error: {msg}",
        );
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
        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &|proof: Vec<u8>, _| {
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

    // ============================================================
    // Issue P0-1 / P0-2 (2026-04-28): ABI-aware strict-mode tests.
    // ============================================================

    /// Build a synthetic proof prefix where:
    ///   * Field 0 = commitment.x
    ///   * Field 1 = commitment.y
    ///   * Field 2..2+32 = nonce_hash bytes (one per slot)
    ///   * Field 34 = csca_root_field (synthetic)
    ///   * Then a suffix of garbage proof bytes.
    fn synthetic_strict_proof(
        commitment: &PedersenPoint,
        nonce_hash: &[u8; 32],
        csca_root_field: &[u8; FIELD_BYTES],
    ) -> (Vec<u8>, usize) {
        let num_fields = 2 + 32 + 1; // x, y, nonce[0..32], csca
        let mut proof = Vec::with_capacity(num_fields * FIELD_BYTES + 16);
        proof.extend_from_slice(&commitment.x);
        proof.extend_from_slice(&commitment.y);
        for b in nonce_hash {
            proof.extend_from_slice(&byte_as_field(*b));
        }
        proof.extend_from_slice(csca_root_field);
        proof.extend_from_slice(&[0xAA; 64]); // suffix
        (proof, num_fields)
    }

    fn fixture_with_strict_layout() -> (PrepareArtifactV3, ShowPresentationV3, PolicyV3) {
        let (mut prepare, mut show, mut policy) = fixture();
        let csca_root = sample_field(0xCC);
        let (prepare_proof, prepare_npi) =
            synthetic_strict_proof(&prepare.commitment, &show.nonce_hash, &csca_root);
        let (show_proof, show_npi) =
            synthetic_strict_proof(&show.commitment, &show.nonce_hash, &csca_root);
        prepare.proof = prepare_proof;
        show.proof = show_proof;

        policy.prepare_layout = PrepareLayoutV3 {
            num_public_inputs: prepare_npi,
            commitment_x_index: 0,
            commitment_y_index: 1,
            extra_pinned_fields: vec![(34, csca_root)],
        };
        policy.show_layout = ShowLayoutV3 {
            num_public_inputs: show_npi,
            commitment_x_index: 0,
            commitment_y_index: 1,
            nonce_hash_first_byte_index: Some(2),
            extra_pinned_fields: vec![(34, csca_root)],
        };
        (prepare, show, policy)
    }

    #[test]
    fn test_strict_layout_happy_path() {
        let (prepare, show, policy) = fixture_with_strict_layout();
        verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect("strict layout should verify");
    }

    #[test]
    fn test_strict_layout_rejects_mismatched_commitment_at_index() {
        // P0-1: even if the prepare commitment bytes appear elsewhere in the
        // proof bytes, they MUST appear at the ABI-known index. Move the
        // commitment off-position and the strict check must reject.
        let (mut prepare, show, policy) = fixture_with_strict_layout();
        // Swap field 0 (commitment.x) and field 33 (last nonce slot) so
        // commitment.x no longer appears at index 0 even though the bytes
        // still exist somewhere in the proof.
        let mut bytes = prepare.proof.clone();
        let f0 = bytes[0..FIELD_BYTES].to_vec();
        let f33_start = 33 * FIELD_BYTES;
        let f33 = bytes[f33_start..f33_start + FIELD_BYTES].to_vec();
        bytes[0..FIELD_BYTES].copy_from_slice(&f33);
        bytes[f33_start..f33_start + FIELD_BYTES].copy_from_slice(&f0);
        prepare.proof = bytes;

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject mismatched commitment index");
        assert!(err.to_string().contains("prepare_commitment_not_in_proof"));
    }

    #[test]
    fn test_strict_layout_rejects_pinned_field_substitution() {
        // P0-2: an adapter pin (csca_root in this fixture) at index 34 must
        // not be replaceable. Flip a byte inside that slot and the strict
        // check must reject before the proof itself is verified.
        let (mut prepare, show, policy) = fixture_with_strict_layout();
        let csca_offset = 34 * FIELD_BYTES;
        prepare.proof[csca_offset] ^= 0x01;

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject pinned field substitution");
        assert!(err.to_string().contains("prepare_public_input_mismatch"));
    }

    #[test]
    fn test_strict_layout_rejects_nonce_byte_substitution() {
        // P0-1: the nonce_hash must appear byte-by-byte at the ABI-known
        // base offset. Flipping a byte AT that offset (where the previous
        // scan would happily find a different nonce elsewhere) must fail.
        let (prepare, mut show, policy) = fixture_with_strict_layout();
        let nonce_byte_offset = (2 + 5) * FIELD_BYTES + (FIELD_BYTES - 1);
        show.proof[nonce_byte_offset] ^= 0x40;

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject nonce-byte substitution");
        assert!(err.to_string().contains("nonce_hash_not_in_proof"));
    }

    #[test]
    fn test_strict_layout_rejects_short_proof() {
        // Strict layout expects at least num_public_inputs * 32 bytes. A
        // truncated proof must fail with proof_too_short_for_public_inputs.
        let (mut prepare, show, policy) = fixture_with_strict_layout();
        prepare.proof.truncate(16); // shorter than even one field

        let err = verify_openac_v3_with_verifier(&prepare, &show, &policy, &always_valid)
            .expect_err("must reject truncated proof");
        assert!(err
            .to_string()
            .contains("proof_too_short_for_public_inputs"));
    }

    // ============================================================
    // Adapter-specific layout builder tests (Task 3, 2026-04-28)
    // ============================================================

    #[test]
    fn test_prepare_layout_passport_pins_required_fields() {
        // Task 3: passport prepare layout must pin csca_root, dsc_smt_root,
        // and exponent (=65537) -- the verifier policy's off-chain trust
        // anchors. The constructor takes them as required arguments.
        let csca_root = sample_field(0xC1);
        let dsc_smt_root = sample_field(0xC2);
        let layout = prepare_layout_passport(csca_root, dsc_smt_root);
        assert_eq!(layout.num_public_inputs, 5);
        assert_eq!(layout.commitment_x_index, 3);
        assert_eq!(layout.commitment_y_index, 4);
        assert_eq!(layout.extra_pinned_fields.len(), 3);
        assert_eq!(layout.extra_pinned_fields[0], (0, csca_root));
        assert_eq!(layout.extra_pinned_fields[1], (1, dsc_smt_root));
        assert_eq!(layout.extra_pinned_fields[2], (2, u32_as_field(65537)));
    }

    #[test]
    fn test_prepare_layout_sdjwt_requires_disclosure_root() {
        // P0-5: out_disclosure_root is the off-chain anchor for the
        // disclosed set. The builder takes it as a required argument so
        // callers cannot construct an sdjwt prepare layout that silently
        // omits the policy pin.
        let issuer_pk_x: [u8; 32] = [1; 32];
        let issuer_pk_y: [u8; 32] = [2; 32];
        let payload_hash: [u8; 32] = [3; 32];
        let sd_hi = sample_field(0xD1);
        let sd_lo = sample_field(0xD2);
        let disclosure_root = sample_field(0xD3);
        let layout = prepare_layout_sdjwt(
            &payload_hash,
            &issuer_pk_x,
            &issuer_pk_y,
            sd_hi,
            sd_lo,
            disclosure_root,
        );
        assert_eq!(layout.num_public_inputs, 101);
        // Disclosure root must be pinned at index 100.
        assert!(
            layout
                .extra_pinned_fields
                .iter()
                .any(|(i, v)| *i == 100 && v == &disclosure_root),
            "disclosure_root must be pinned at field index 100",
        );
    }

    #[test]
    fn test_prepare_layout_jwt_x5c_requires_payload_b64h_and_signed_hash() {
        // P0-4 residual gap: jwt_payload_b64h and jwt_signed_hash are
        // required policy pins because the in-circuit binding only proves
        // each is the SHA256 of a prover-supplied buffer; the verifier
        // policy MUST tie them to a known off-chain JWT.
        let payload_b64h: [u8; 32] = [11; 32];
        let signed_hash: [u8; 32] = [22; 32];
        let modulus: [u128; 18] = [33; 18];
        let smt_root = sample_field(0x44);
        let issuer_tag = sample_field(0x55);
        let layout =
            prepare_layout_jwt_x5c(&payload_b64h, &signed_hash, &modulus, smt_root, issuer_tag);
        assert_eq!(layout.num_public_inputs, 86);
        // Each byte of payload_b64h appears at indices 0..32.
        for i in 0..32 {
            let pin = layout
                .extra_pinned_fields
                .iter()
                .find(|(idx, _)| *idx == i)
                .expect("payload_b64h byte must be pinned");
            assert_eq!(pin.1, byte_as_field(payload_b64h[i]));
        }
        // Each byte of signed_hash appears at indices 32..64.
        for i in 0..32 {
            let pin = layout
                .extra_pinned_fields
                .iter()
                .find(|(idx, _)| *idx == 32 + i)
                .expect("signed_hash byte must be pinned");
            assert_eq!(pin.1, byte_as_field(signed_hash[i]));
        }
    }

    #[test]
    fn test_show_layout_openac_pins_credential_type_to_passport() {
        // P1-8: openac_show only accepts DOMAIN_PASSPORT. The builder pins
        // credential_type at field index 0 to byte_as_field(DOMAIN_PASSPORT)
        // so a verifier cannot accidentally accept an X.509 / SDJWT
        // commitment opening from the same circuit.
        let scope = sample_field(0xE0);
        let epoch = [0x20, 0x26, 0x04, 0x28];
        let epoch_field = sample_field(0xE1);
        let digest = sample_hash32(0xE2);
        let link_tag = sample_field(0xE3);
        let layout = show_layout_openac(true, scope, &epoch, epoch_field, &digest, link_tag);
        assert_eq!(layout.num_public_inputs, 85);
        assert_eq!(layout.commitment_x_index, 46);
        assert_eq!(layout.commitment_y_index, 47);
        assert_eq!(layout.nonce_hash_first_byte_index, Some(1));
        assert!(layout
            .extra_pinned_fields
            .contains(&(0, byte_as_field(DOMAIN_PASSPORT))));
        assert!(layout
            .extra_pinned_fields
            .contains(&(33, bool_as_field(true))));
        assert!(layout.extra_pinned_fields.contains(&(34, scope)));
        for pin in pin_byte_array(35, &epoch) {
            assert!(layout.extra_pinned_fields.contains(&pin));
        }
        assert!(layout.extra_pinned_fields.contains(&(39, epoch_field)));
    }

    #[test]
    fn test_show_layout_openac_pins_challenge_digest_and_link_tag() {
        let scope = sample_field(0xE0);
        let epoch = [0x20, 0x26, 0x04, 0x28];
        let epoch_field = sample_field(0xE3);
        let digest = sample_hash32(0xE1);
        let link_tag = sample_field(0xE2);
        let layout = show_layout_openac(true, scope, &epoch, epoch_field, &digest, link_tag);
        for pin in pin_byte_array(48, &digest) {
            assert!(
                layout.extra_pinned_fields.contains(&pin),
                "challenge digest byte must be pinned at field index {}",
                pin.0,
            );
        }
        assert!(
            layout.extra_pinned_fields.contains(&(80, link_tag)),
            "link tag must be pinned at field index 80",
        );
    }

    #[test]
    fn test_show_layout_x509_pins_target_domain_hash() {
        let target = sample_field(0x70);
        let scope = sample_field(0x71);
        let epoch = sample_field(0x72);
        let tag = sample_field(0x73);
        let digest = sample_field(0x74);
        let layout = show_layout_x509(target, true, scope, epoch, tag, digest);
        assert_eq!(layout.num_public_inputs, 41);
        assert!(layout.extra_pinned_fields.contains(&(34, target)));
        assert!(layout
            .extra_pinned_fields
            .contains(&(35, bool_as_field(true))));
        assert!(layout.extra_pinned_fields.contains(&(36, scope)));
        assert!(layout.extra_pinned_fields.contains(&(37, epoch)));
        assert!(layout.extra_pinned_fields.contains(&(38, tag)));
        assert!(layout.extra_pinned_fields.contains(&(40, digest)));
    }

    #[test]
    fn test_show_layout_composite_pins_aux_commitment_and_target_hash() {
        let aux_commitment = sample_point(0x81);
        let aux_domain = byte_as_field(DOMAIN_X509);
        let target = sample_field(0x82);
        let scope = sample_field(0x83);
        let epoch = sample_field(0x84);
        let tag = sample_field(0x85);
        let digest = sample_field(0x86);
        let layout = show_layout_composite(
            &aux_commitment,
            aux_domain,
            target,
            true,
            scope,
            epoch,
            tag,
            digest,
        );
        assert_eq!(layout.num_public_inputs, 49);
        assert!(layout.extra_pinned_fields.contains(&(2, aux_commitment.x)));
        assert!(layout.extra_pinned_fields.contains(&(3, aux_commitment.y)));
        assert!(layout.extra_pinned_fields.contains(&(4, aux_domain)));
        assert!(layout.extra_pinned_fields.contains(&(41, target)));
        assert!(layout
            .extra_pinned_fields
            .contains(&(42, bool_as_field(true))));
        assert!(layout.extra_pinned_fields.contains(&(43, scope)));
        assert!(layout.extra_pinned_fields.contains(&(44, epoch)));
        assert!(layout.extra_pinned_fields.contains(&(45, tag)));
        assert!(layout.extra_pinned_fields.contains(&(48, digest)));
    }
}
