//! OpenAC v3 passport witness builder.
//!
//! Input: the canonical witness-request JSON the app's NFC layer emits
//! (`gg.solidarity.passport.openac-v3.witness-request.v1`). Output: a
//! result JSON that is `ready=false` with a fail-closed reason, or
//! `ready=true` with a `bundleJson` carrying complete witness-input maps for
//! the three passport-noir 0.3.0 circuits (`dsc_chain`, `passport_adapter`,
//! `openac_show`). The openac_show map ships a placeholder device
//! `signature`; the app binds the real Secure-Enclave ECDSA signature over
//! `nonce_hash` just before proving.
//!
//! Trust layering (each gate fails closed):
//!   1. `passiveAuthValid` — native passive authentication against the
//!      bundled CSCA Master List already verified the REAL chain.
//!   2. `sod.rs` re-verifies the chip DG1/DG15 bytes against the SOD's LDS
//!      hashes (and the CMS messageDigest ↔ eContent link).
//!   3. The Master List CSCA metadata (shipped inside the revocation
//!      snapshot) must contain the DSC's issuing CSCA; its index/TBS digest
//!      are bound into the in-circuit Merkle leaf.
//!   4. The REAL DSC serial must prove non-membership in the depth-32 SMT
//!      built from the REAL CRL snapshot entries of that CSCA.
//!   5. DG15 Active Authentication (ECDSA-P256 over a fresh challenge) is
//!      pre-verified off-circuit and then proven in-circuit.
//!
//! The in-circuit RSA chain itself is a per-request attestation chain (see
//! `attestation.rs` for why real ICAO signatures cannot satisfy the
//! normalised 0.3.0 layouts).

pub(crate) mod attestation;
#[cfg(test)]
pub(crate) mod fixtures;
pub(crate) mod pedersen;
pub(crate) mod sod;
pub(crate) mod trust;

use crate::MoproError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use noir_rs::acir::{AcirField, FieldElement};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use attestation::AttestationChain;
use sod::{AaPublicKey, SodError};

const REQUEST_SCHEMA: &str = "gg.solidarity.passport.openac-v3.witness-request.v1";
const RESULT_SCHEMA: &str = "gg.solidarity.passport.openac-v3.witness-build-result.v1";
const PASSPORT_NOIR_VERSION: &str = "0.3.0";

/// Domain separator for mapping the app's linkScope string to a Field.
const SCOPE_FIELD_DOMAIN: &[u8] = b"solidarity.openac.scope.v1";

/// Product policy mirrored from the app flow: scoped linking, adult check,
/// nationality disclosure. These are public inputs the verifier pins.
const AGE_THRESHOLD: u32 = 18;
const DISCLOSE_AGE: bool = true;
const DISCLOSE_NATIONALITY: bool = true;
const LINK_MODE_SCOPED: bool = true;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenAcV3WitnessRequest {
    schema: String,
    passport_noir_version: String,
    passive_auth_valid: bool,
    data_groups: BTreeMap<String, String>,
    revocation_snapshot: Value,
    device_public_key_raw_b64: String,
    nonce_hash_b64: String,
    link_scope: String,
    #[serde(rename = "requireAA")]
    require_aa: bool,
    #[serde(default)]
    active_auth: Option<OpenAcV3ActiveAuthEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenAcV3ActiveAuthEvidence {
    /// SHA-256 digest of the chip-signed AA challenge (the ECDSA message
    /// digest the circuit pins as the public `aa_challenge`).
    challenge_b64: String,
    /// Raw 64-byte `r ‖ s` ECDSA-P256 signature from INTERNAL AUTHENTICATE.
    signature_raw_b64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenAcV3WitnessBuildResult {
    schema: &'static str,
    passport_noir_version: &'static str,
    ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_json: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenAcV3WitnessBundle {
    dsc_chain_inputs_json: String,
    passport_adapter_inputs_json: String,
    open_ac_show_inputs_json: String,
}

/// UniFFI entry point — generates fresh attestation keys per request.
#[uniffi::export]
pub fn build_open_ac_v3_witness_bundle(request_json: String) -> Result<String, MoproError> {
    build_bundle(&request_json, None)
}

/// Test/bench entry point with injected attestation keys (skips RSA keygen).
#[allow(dead_code)]
pub fn build_open_ac_v3_witness_bundle_with_keys(
    request_json: &str,
    csca_key: rsa::RsaPrivateKey,
    dsc_key: rsa::RsaPrivateKey,
) -> Result<String, MoproError> {
    build_bundle(request_json, Some((csca_key, dsc_key)))
}

fn build_bundle(
    request_json: &str,
    keys: Option<(rsa::RsaPrivateKey, rsa::RsaPrivateKey)>,
) -> Result<String, MoproError> {
    let request: OpenAcV3WitnessRequest = serde_json::from_str(request_json)
        .map_err(|e| MoproError::InvalidInput(format!("invalid witness request JSON: {e}")))?;

    match witnesses_for_request(&request, keys) {
        Ok(bundle) => {
            let bundle_json = serde_json::to_string(&bundle).map_err(|e| {
                MoproError::InvalidInput(format!("failed to encode witness bundle: {e}"))
            })?;
            serde_json::to_string(&OpenAcV3WitnessBuildResult {
                schema: RESULT_SCHEMA,
                passport_noir_version: PASSPORT_NOIR_VERSION,
                ready: true,
                reason: None,
                bundle_json: Some(bundle_json),
            })
            .map_err(|e| MoproError::InvalidInput(format!("failed to encode witness result: {e}")))
        }
        Err(reason) => unavailable(reason),
    }
}

fn witnesses_for_request(
    request: &OpenAcV3WitnessRequest,
    keys: Option<(rsa::RsaPrivateKey, rsa::RsaPrivateKey)>,
) -> Result<OpenAcV3WitnessBundle, &'static str> {
    // ── Shape gates (kept in the historical order the app's tests pin) ──
    if request.schema != REQUEST_SCHEMA {
        return Err("invalid-request-schema");
    }
    if request.passport_noir_version != PASSPORT_NOIR_VERSION {
        return Err("unsupported-passport-noir-version");
    }
    if !request.passive_auth_valid {
        return Err("passive-auth-failed");
    }
    if request.link_scope.trim().is_empty() {
        return Err("missing-link-scope");
    }

    let mut dg_bytes: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    for name in ["sod", "dg1"] {
        let Some(encoded) = request.data_groups.get(name) else {
            return Err(match name {
                "sod" => "missing-sod",
                _ => "missing-dg1",
            });
        };
        let Ok(bytes) = decode_non_empty_b64(encoded) else {
            return Err(match name {
                "sod" => "invalid-sod",
                _ => "invalid-dg1",
            });
        };
        dg_bytes.insert(name, bytes);
    }
    let dg15_bytes = match request.data_groups.get("dg15") {
        Some(encoded) => Some(decode_non_empty_b64(encoded).map_err(|_| "invalid-dg15")?),
        None => None,
    };
    if request.require_aa && dg15_bytes.is_none() {
        return Err("missing-dg15");
    }

    let Ok(device_pk) = decode_exact_b64(&request.device_public_key_raw_b64, 64) else {
        return Err("invalid-device-public-key");
    };
    let Ok(nonce_hash) = decode_exact_b64(&request.nonce_hash_b64, 32) else {
        return Err("invalid-nonce-hash");
    };
    if !is_revocation_snapshot_present(&request.revocation_snapshot) {
        return Err("missing-revocation-snapshot");
    }
    let active_auth = match request.active_auth.as_ref() {
        Some(active_auth) => {
            let Ok(challenge) = decode_exact_b64(&active_auth.challenge_b64, 32) else {
                return Err("invalid-active-auth-challenge");
            };
            let Ok(signature) = decode_exact_b64(&active_auth.signature_raw_b64, 64) else {
                return Err("invalid-active-auth-signature");
            };
            Some((challenge, signature))
        }
        None if request.require_aa => return Err("missing-active-auth-witness"),
        None => None,
    };

    // ── Device key must be a real P-256 point (the show circuit ECDSA-
    // verifies with it; a bad point would only explode inside the prover). ──
    let device_pk_x: [u8; 32] = device_pk[..32].try_into().expect("len checked");
    let device_pk_y: [u8; 32] = device_pk[32..].try_into().expect("len checked");
    if p256_verifying_key(&device_pk_x, &device_pk_y).is_none() {
        return Err("invalid-device-public-key");
    }

    // ── Chip files: SOD ↔ DG integrity, MRZ claims, AA public key. ──
    let sod_bytes = &dg_bytes["sod"];
    let dg1_bytes = &dg_bytes["dg1"];
    let dg15_bytes = dg15_bytes.as_deref();
    let dg_count = if dg15_bytes.is_some() { 2 } else { 1 };

    let parsed_sod =
        sod::parse_sod_optional_dg15(sod_bytes, dg1_bytes, dg15_bytes).map_err(reason_for_sod)?;
    let mrz = sod::parse_dg1_mrz(dg1_bytes).map_err(reason_for_sod)?;
    let claims = sod::mrz_claims(&mrz).map_err(reason_for_sod)?;
    // ── AA slot witnesses + pre-verification (fail closed before the prover
    // ever sees an invalid witness). The circuit always evaluates the
    // secp256r1 blackbox on this slot — Noir cannot drop the call when
    // require_aa = false — and the barretenberg gadget can only CONSTRAIN a
    // succeeding verification: any non-verifying (key, challenge, signature)
    // triple still produces a proof, but one that fails verification. The
    // acvm solver additionally refuses an off-curve key outright ("Invalid
    // public key provided for ECDSA verification", surfaced under the
    // mislabeled upstream name `ecdsa_secp256k1` — the build 28 field
    // report). So every path below must emit a triple that VERIFIES:
    //   - DG15 + AA evidence: the chip's real, pre-verified signature.
    //   - DG15 without evidence: fail closed — we cannot sign under the
    //     chip's key, and the chain-bound slot must never hold a key whose
    //     private half is public knowledge.
    //   - No DG15 (require_aa = false enforced above): the fixed placeholder
    //     triple; dg_count = 1 keeps it out of the DG hash chain, so it
    //     carries no authority.
    let (aa_pk_x, aa_pk_y, aa_challenge, aa_signature): ([u8; 32], [u8; 32], [u8; 32], [u8; 64]) =
        match (dg15_bytes, &active_auth) {
            (Some(dg15), Some((challenge, signature))) => {
                let AaPublicKey::P256 { x, y } =
                    sod::parse_dg15_aa_key(dg15).map_err(reason_for_sod)?;
                let challenge: [u8; 32] = challenge.as_slice().try_into().expect("len checked");
                let signature: [u8; 64] = signature.as_slice().try_into().expect("len checked");
                let Some(aa_key) = p256_verifying_key(&x, &y) else {
                    return Err("active-auth-unsupported-key");
                };
                if !p256_verify_prehash(&aa_key, &challenge, &signature) {
                    return Err("invalid-active-auth-signature");
                }
                // Barretenberg's ecdsa_secp256r1 blackbox rejects high-S
                // signatures (malleability guard). ICAO chips do not mandate
                // low-S, so normalize before the circuit sees it — ECDSA
                // verification is agnostic to the S sign, so this stays sound.
                (x, y, challenge, normalize_low_s(&signature))
            }
            (Some(_), None) => return Err("missing-active-auth-witness"),
            (None, _) => {
                let (x, y, signature) = placeholder_aa_witness();
                (x, y, passive_aa_challenge(), signature)
            }
        };

    // ── Master List CSCA metadata match (real CSCA identity binding). ──
    let csca_meta = match_csca_metadata(&request.revocation_snapshot, &parsed_sod.dsc)?;

    // ── Per-request attestation chain. ──
    let chain = match keys {
        Some((csca_key, dsc_key)) => AttestationChain::build_with_keys(
            csca_key,
            dsc_key,
            &csca_meta.tbs_sha256,
            &parsed_sod.dsc.tbs_sha256,
            &parsed_sod.dsc.serial20,
        ),
        None => AttestationChain::generate(
            &csca_meta.tbs_sha256,
            &parsed_sod.dsc.tbs_sha256,
            &parsed_sod.dsc.serial20,
        ),
    }
    .map_err(|_| "attestation-chain-failed")?;

    // ── CSCA Master List inclusion (leaf binds the REAL CSCA TBS digest). ──
    let (csca_tbs_hi, csca_tbs_lo) = pedersen::hash_to_fields(&csca_meta.tbs_sha256);
    let csca_leaf =
        pedersen::compute_csca_leaf_v2(&chain.csca_modulus_limbs, 65537, csca_tbs_hi, csca_tbs_lo);
    let inclusion = trust::csca_single_leaf_inclusion(csca_leaf, csca_meta.index);

    // ── Revocation SMT over the REAL CRL serials of the matched CSCA. ──
    let revoked_serials = issuer_revoked_serials(&request.revocation_snapshot, &parsed_sod.dsc)?;
    let smt = trust::RevocationSmt::build(csca_leaf, &revoked_serials);
    let serial_key = pedersen::compute_serial_key(csca_leaf, &parsed_sod.dsc.serial20);
    let non_membership = smt
        .prove_non_membership(serial_key)
        .map_err(|_| "dsc-revoked")?;

    // ── Normalised DG layout + sod_hash (passport_adapter sec.7.3). ──
    let dg1_content = mrz; // 88-byte MRZ, zero-padded to 512 by the circuit
    let mut dg15_content = [0u8; 64];
    dg15_content[..32].copy_from_slice(&aa_pk_x);
    dg15_content[32..].copy_from_slice(&aa_pk_y);

    let dg1_hash = padded_dg_hash(&dg1_content);
    let dg15_hash = padded_dg_hash(&dg15_content);
    let sod_hash: [u8; 32] = {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&dg1_hash);
        if dg_count > 1 {
            preimage[32..].copy_from_slice(&dg15_hash);
        }
        Sha256::digest(preimage).into()
    };
    let sod_sig_limbs = chain
        .sign_sod_hash(&sod_hash)
        .map_err(|_| "attestation-chain-failed")?;

    // ── Commitment inputs. ──
    let claims_field = pack_passport_claims(&claims);
    let (sod_hi, sod_lo) = pedersen::hash_to_fields(&sod_hash);
    let (dg1_hi, dg1_lo) = pedersen::hash_to_fields(&dg1_hash);
    let pk_digest = pedersen::pk_digest_from_bytes(&device_pk_x, &device_pk_y);
    let scope_field = scope_to_field(&request.link_scope);
    let link_rand_seed = random_field();
    let link_rand = pedersen::derive_scoped_link_rand(link_rand_seed, scope_field);
    let (commitment_x, commitment_y) = pedersen::commit_passport_v3_1(
        claims_field,
        sod_hi,
        sod_lo,
        dg1_hi,
        dg1_lo,
        pk_digest,
        link_rand,
    );

    // ── Show context: real current date, date-derived epoch, link tag. ──
    let (year, month, day) = utc_today();
    let epoch = FieldElement::from((year as u128) * 10_000 + (month as u128) * 100 + day as u128);
    let link_tag = pedersen::compute_link_tag(
        pedersen::field(pedersen::DOMAIN_PASSPORT),
        link_rand,
        scope_field,
        epoch,
    );
    let is_older = age_at_least(&claims, year, month, day, AGE_THRESHOLD);
    let nonce_hash: [u8; 32] = nonce_hash.as_slice().try_into().expect("len checked");

    // ── Emit the three circuit input maps. ──
    let dsc_chain_inputs = dsc_chain_inputs(&chain, &inclusion, &non_membership, &parsed_sod);
    let passport_adapter_inputs = passport_adapter_inputs(
        &chain,
        &sod_sig_limbs,
        &sod_hash,
        &dg1_content,
        &dg15_content,
        &dg1_hash,
        &dg15_hash,
        dg_count,
        link_rand_seed,
        &device_pk_x,
        &device_pk_y,
        &aa_signature,
        &aa_challenge,
        request.require_aa,
        scope_field,
        commitment_x,
        commitment_y,
    );
    let openac_show_inputs = openac_show_inputs(
        claims_field,
        sod_hi,
        sod_lo,
        dg1_hi,
        dg1_lo,
        link_rand,
        &device_pk_x,
        &device_pk_y,
        &nonce_hash,
        scope_field,
        epoch,
        (year, month, day),
        is_older,
        &claims.nationality,
        commitment_x,
        commitment_y,
        link_tag,
    );

    Ok(OpenAcV3WitnessBundle {
        dsc_chain_inputs_json: serde_json::to_string(&dsc_chain_inputs)
            .expect("input map serializes"),
        passport_adapter_inputs_json: serde_json::to_string(&passport_adapter_inputs)
            .expect("input map serializes"),
        open_ac_show_inputs_json: serde_json::to_string(&openac_show_inputs)
            .expect("input map serializes"),
    })
}

// ---------------------------------------------------------------------------
// Witness-input maps (name → Vec<decimal-string>, flattened per Noir ABI)
// ---------------------------------------------------------------------------

type InputMap = BTreeMap<&'static str, Vec<String>>;

fn field_str(field: FieldElement) -> String {
    num_bigint::BigUint::from_bytes_be(&field.to_be_bytes()).to_str_radix(10)
}

fn fields(values: &[FieldElement]) -> Vec<String> {
    values.iter().map(|f| field_str(*f)).collect()
}

fn bytes(values: &[u8]) -> Vec<String> {
    values.iter().map(|b| b.to_string()).collect()
}

fn single(value: impl ToString) -> Vec<String> {
    vec![value.to_string()]
}

fn bool_str(value: bool) -> Vec<String> {
    single(if value { "1" } else { "0" })
}

fn dsc_chain_inputs(
    chain: &AttestationChain,
    inclusion: &trust::CscaInclusion,
    non_membership: &trust::SmtNonMembership,
    parsed_sod: &sod::ParsedSod,
) -> InputMap {
    let mut map = InputMap::new();
    map.insert("csca_modulus_limbs", fields(&chain.csca_modulus_limbs));
    map.insert("csca_redc_limbs", fields(&chain.csca_redc_limbs));
    map.insert("dsc_tbs", bytes(&chain.dsc_tbs));
    map.insert("dsc_cert_sig_limbs", fields(&chain.dsc_cert_sig_limbs));
    map.insert("csca_merkle_index", single(inclusion.index));
    map.insert("csca_merkle_siblings", fields(&inclusion.siblings));
    let (hi, lo) = pedersen::hash_to_fields(&{
        // leaf binds the REAL CSCA TBS digest; recompute the halves here so
        // the input map cannot drift from the leaf construction.
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&chain.dsc_tbs[320..352]);
        digest
    });
    map.insert("csca_tbs_hash_hi", single(field_str(hi)));
    map.insert("csca_tbs_hash_lo", single(field_str(lo)));
    map.insert("dsc_serial", bytes(&parsed_sod.dsc.serial20));
    map.insert("smt_siblings", fields(&non_membership.siblings));
    map.insert("smt_old_key", single(field_str(non_membership.old_key)));
    map.insert("smt_old_value", single(field_str(non_membership.old_value)));
    map.insert("smt_is_old0", bool_str(non_membership.is_old0));
    map.insert("csca_root", single(field_str(inclusion.root)));
    map.insert("dsc_smt_root", single(field_str(non_membership.root)));
    map.insert("exponent", single(65537u32));
    map.insert("out_dsc_id", single(field_str(chain.dsc_id)));
    map
}

#[allow(clippy::too_many_arguments)]
fn passport_adapter_inputs(
    chain: &AttestationChain,
    sod_sig_limbs: &[FieldElement; 18],
    sod_hash: &[u8; 32],
    dg1_content: &[u8; 88],
    dg15_content: &[u8; 64],
    dg1_hash: &[u8; 32],
    dg15_hash: &[u8; 32],
    dg_count: u8,
    link_rand_seed: FieldElement,
    device_pk_x: &[u8; 32],
    device_pk_y: &[u8; 32],
    aa_signature: &[u8; 64],
    aa_challenge: &[u8; 32],
    require_aa: bool,
    scope_field: FieldElement,
    commitment_x: FieldElement,
    commitment_y: FieldElement,
) -> InputMap {
    const MAX_DG_SIZE: usize = 512;

    let mut dg_contents = Vec::with_capacity(2 * MAX_DG_SIZE);
    let mut dg1_padded = [0u8; MAX_DG_SIZE];
    dg1_padded[..dg1_content.len()].copy_from_slice(dg1_content);
    dg_contents.extend_from_slice(&dg1_padded);
    let mut dg15_padded = [0u8; MAX_DG_SIZE];
    dg15_padded[..dg15_content.len()].copy_from_slice(dg15_content);
    dg_contents.extend_from_slice(&dg15_padded);

    let mut expected_hashes = Vec::with_capacity(64);
    expected_hashes.extend_from_slice(dg1_hash);
    if dg_count > 1 {
        expected_hashes.extend_from_slice(dg15_hash);
    } else {
        expected_hashes.extend_from_slice(&[0u8; 32]);
    }

    let mut map = InputMap::new();
    map.insert("sod_hash", bytes(sod_hash));
    map.insert("signature_limbs", fields(sod_sig_limbs));
    map.insert("modulus_limbs", fields(&chain.dsc_modulus_limbs));
    map.insert("redc_limbs", fields(&chain.dsc_redc_limbs));
    map.insert("dg_count", single(dg_count));
    map.insert("dg_contents", bytes(&dg_contents));
    map.insert(
        "dg_lengths",
        vec![
            dg1_content.len().to_string(),
            if dg_count > 1 { dg15_content.len() } else { 0 }.to_string(),
        ],
    );
    map.insert("expected_dg_hashes", bytes(&expected_hashes));
    map.insert("link_rand_seed", single(field_str(link_rand_seed)));
    map.insert("enclave_pk_x", bytes(device_pk_x));
    map.insert("enclave_pk_y", bytes(device_pk_y));
    map.insert("aa_signature", bytes(aa_signature));
    map.insert("in_dsc_id", single(field_str(chain.dsc_id)));
    map.insert("exponent", single(65537u32));
    map.insert("link_scope", single(field_str(scope_field)));
    map.insert("require_aa", bool_str(require_aa));
    map.insert("aa_challenge", bytes(aa_challenge));
    map.insert("out_commitment_x", single(field_str(commitment_x)));
    map.insert("out_commitment_y", single(field_str(commitment_y)));
    map
}

#[allow(clippy::too_many_arguments)]
fn openac_show_inputs(
    claims_field: FieldElement,
    sod_hi: FieldElement,
    sod_lo: FieldElement,
    dg1_hi: FieldElement,
    dg1_lo: FieldElement,
    link_rand: FieldElement,
    device_pk_x: &[u8; 32],
    device_pk_y: &[u8; 32],
    nonce_hash: &[u8; 32],
    scope_field: FieldElement,
    epoch: FieldElement,
    today: (u32, u32, u32),
    is_older: bool,
    nationality: &[u8; 3],
    commitment_x: FieldElement,
    commitment_y: FieldElement,
    link_tag: FieldElement,
) -> InputMap {
    let mut map = InputMap::new();
    map.insert("claims", single(field_str(claims_field)));
    map.insert("sod_hash_hi", single(field_str(sod_hi)));
    map.insert("sod_hash_lo", single(field_str(sod_lo)));
    map.insert("dg1_hash_hi", single(field_str(dg1_hi)));
    map.insert("dg1_hash_lo", single(field_str(dg1_lo)));
    map.insert("link_rand", single(field_str(link_rand)));
    map.insert("enclave_pk_x", bytes(device_pk_x));
    map.insert("enclave_pk_y", bytes(device_pk_y));
    // Placeholder — replaced by the app with the Secure-Enclave ECDSA
    // signature over nonce_hash before proving (the circuit asserts it).
    map.insert("signature", bytes(&placeholder_signature()));
    map.insert("credential_type", single(pedersen::DOMAIN_PASSPORT));
    map.insert("nonce_hash", bytes(nonce_hash));
    map.insert("link_mode", bool_str(LINK_MODE_SCOPED));
    map.insert("link_scope", single(field_str(scope_field)));
    map.insert("epoch", single(field_str(epoch)));
    map.insert("current_year", single(today.0));
    map.insert("current_month", single(today.1));
    map.insert("current_day", single(today.2));
    map.insert("age_threshold", single(AGE_THRESHOLD));
    map.insert("disclose_nationality", bool_str(DISCLOSE_NATIONALITY));
    map.insert("disclose_age", bool_str(DISCLOSE_AGE));
    map.insert("out_commitment_x", single(field_str(commitment_x)));
    map.insert("out_commitment_y", single(field_str(commitment_y)));
    map.insert("out_link_tag", single(field_str(link_tag)));
    map.insert("out_is_older", bool_str(is_older));
    map.insert(
        "out_nationality",
        if DISCLOSE_NATIONALITY {
            bytes(nationality)
        } else {
            bytes(&[0, 0, 0])
        },
    );
    map
}

// ---------------------------------------------------------------------------
// Snapshot matching
// ---------------------------------------------------------------------------

struct CscaMetadataMatch {
    index: u32,
    tbs_sha256: [u8; 32],
}

/// Locate the DSC's issuing CSCA inside the Master List metadata the
/// revocation snapshot carries (`cscaMetadata.cscas[]`, emitted by
/// scripts/generate_masterlist.py). Match by SubjectKeyIdentifier ↔
/// AuthorityKeyIdentifier first, then by issuer-Name DER digest.
fn match_csca_metadata(
    snapshot: &Value,
    dsc: &sod::ParsedDsc,
) -> Result<CscaMetadataMatch, &'static str> {
    let metadata = snapshot
        .get("cscaMetadata")
        .and_then(Value::as_object)
        .ok_or("missing-csca-metadata")?;
    let cscas = metadata
        .get("cscas")
        .and_then(Value::as_array)
        .ok_or("missing-csca-metadata")?;

    let issuer_der_hex = sod::hex_upper(&dsc.issuer_name_der_sha256);

    for entry in cscas {
        let Some(entry) = entry.as_object() else {
            return Err("invalid-csca-metadata");
        };
        let ski_match = match (
            dsc.authority_key_id_hex.as_deref(),
            entry.get("subjectKeyIdentifierHex").and_then(Value::as_str),
        ) {
            (Some(aki), Some(ski)) => aki.eq_ignore_ascii_case(ski),
            _ => false,
        };
        let name_match = entry
            .get("subjectNameDerSha256Hex")
            .and_then(Value::as_str)
            .map(|hex| hex.eq_ignore_ascii_case(&issuer_der_hex))
            .unwrap_or(false);
        if !(ski_match || name_match) {
            continue;
        }

        let index = entry
            .get("index")
            .and_then(Value::as_u64)
            .filter(|i| *i < 256)
            .ok_or("invalid-csca-metadata")?;
        let tbs_hex = entry
            .get("tbsSha256Hex")
            .and_then(Value::as_str)
            .ok_or("invalid-csca-metadata")?;
        let tbs_sha256 = parse_hex_32(tbs_hex).ok_or("invalid-csca-metadata")?;
        return Ok(CscaMetadataMatch {
            index: index as u32,
            tbs_sha256,
        });
    }

    Err("csca-not-in-masterlist")
}

/// Revoked serials of the DSC's issuing CSCA, matched per entry by AKI or by
/// issuer-Name DER digest (`issuerNameDerSha256Hex`, emitted by the
/// masterlist script alongside the legacy string-form hash).
fn issuer_revoked_serials(
    snapshot: &Value,
    dsc: &sod::ParsedDsc,
) -> Result<Vec<[u8; 20]>, &'static str> {
    let entries = snapshot
        .get("entries")
        .and_then(Value::as_array)
        .ok_or("missing-revocation-snapshot")?;
    let issuer_der_hex = sod::hex_upper(&dsc.issuer_name_der_sha256);

    let mut serials = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return Err("invalid-revocation-snapshot");
        };
        let aki_match = match (
            dsc.authority_key_id_hex.as_deref(),
            entry
                .get("authorityKeyIdentifierHex")
                .and_then(Value::as_str),
        ) {
            (Some(aki), Some(entry_aki)) => aki.eq_ignore_ascii_case(entry_aki),
            _ => false,
        };
        let name_match = entry
            .get("issuerNameDerSha256Hex")
            .and_then(Value::as_str)
            .map(|hex| hex.eq_ignore_ascii_case(&issuer_der_hex))
            .unwrap_or(false);
        if !(aki_match || name_match) {
            continue;
        }
        let serial_hex = entry
            .get("serial20Hex")
            .and_then(Value::as_str)
            .ok_or("invalid-revocation-snapshot")?;
        let serial = parse_hex_20(serial_hex).ok_or("invalid-revocation-snapshot")?;
        serials.push(serial);
    }
    Ok(serials)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reason_for_sod(error: SodError) -> &'static str {
    match error {
        SodError::InvalidSod => "invalid-sod",
        SodError::UnsupportedLdsDigest => "unsupported-lds-digest",
        SodError::MissingDgHash => "missing-dg-hash",
        SodError::MissingDg15 => "missing-dg15",
        SodError::DgHashMismatch => "sod-dg-hash-mismatch",
        SodError::InvalidDscCert => "invalid-dsc-cert",
        SodError::DscSerialTooLong => "dsc-serial-too-long",
        SodError::InvalidDg1 => "invalid-dg1",
        SodError::InvalidDg15 => "invalid-dg15",
        SodError::UnsupportedAaKey => "active-auth-unsupported-key",
    }
}

fn unavailable(reason: &'static str) -> Result<String, MoproError> {
    serde_json::to_string(&OpenAcV3WitnessBuildResult {
        schema: RESULT_SCHEMA,
        passport_noir_version: PASSPORT_NOIR_VERSION,
        ready: false,
        reason: Some(reason),
        bundle_json: None,
    })
    .map_err(|e| MoproError::InvalidInput(format!("failed to encode witness result: {e}")))
}

fn decode_non_empty_b64(value: &str) -> Result<Vec<u8>, ()> {
    let bytes = STANDARD.decode(value).map_err(|_| ())?;
    if bytes.is_empty() {
        return Err(());
    }
    Ok(bytes)
}

fn decode_exact_b64(value: &str, len: usize) -> Result<Vec<u8>, ()> {
    let bytes = decode_non_empty_b64(value)?;
    if bytes.len() != len {
        return Err(());
    }
    Ok(bytes)
}

fn is_revocation_snapshot_present(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    obj.get("schema").and_then(Value::as_str) == Some("gg.solidarity.passport.revocation.v1")
        && obj.get("sources").and_then(Value::as_array).is_some()
        && obj.get("entries").and_then(Value::as_array).is_some()
}

fn parse_hex_32(hex: &str) -> Option<[u8; 32]> {
    parse_hex::<32>(hex)
}

fn parse_hex_20(hex: &str) -> Option<[u8; 20]> {
    parse_hex::<20>(hex)
}

fn parse_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn p256_verifying_key(x: &[u8; 32], y: &[u8; 32]) -> Option<p256::ecdsa::VerifyingKey> {
    let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    p256::ecdsa::VerifyingKey::from_encoded_point(&point).ok()
}

fn p256_verify_prehash(
    key: &p256::ecdsa::VerifyingKey,
    digest32: &[u8; 32],
    signature_raw: &[u8; 64],
) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature_raw) else {
        return false;
    };
    key.verify_prehash(digest32, &signature).is_ok()
}

/// Normalize an ECDSA-P256 signature to its low-S form. Barretenberg's
/// `ecdsa_secp256r1` blackbox enforces low-S; a high-S signature would make
/// the in-circuit `verify_signature` fail even though it is mathematically
/// valid. Returns the canonical 64-byte `r ‖ s` with `s <= n/2`.
fn normalize_low_s(signature_raw: &[u8; 64]) -> [u8; 64] {
    match p256::ecdsa::Signature::from_slice(signature_raw) {
        Ok(signature) => signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into(),
        // Unparseable signatures only reach here on the require_aa=false
        // placeholder path, which never asserts; pass through unchanged.
        Err(_) => *signature_raw,
    }
}

/// Structurally-valid-but-never-verifying ECDSA signature (r = s = 1) so the
/// unasserted blackbox path stays solvable when AA is not required.
fn placeholder_signature() -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[31] = 1;
    sig[63] = 1;
    sig
}

/// Fixed non-zero challenge for the passive-only (`require_aa = false`) AA
/// slot. Companion of `placeholder_signature`: the in-circuit secp256r1
/// gadget needs a non-zero hashed message (z = 0 degenerates into a
/// zero-scalar mul its incomplete formulas cannot constrain), and the value
/// is a public input, so a fixed domain digest documents itself to
/// verifiers.
fn passive_aa_challenge() -> [u8; 32] {
    Sha256::digest(b"solidarity.openac.passive-aa-placeholder.v1").into()
}

/// Deterministic AA placeholder triple for the passive-only path
/// (`require_aa = false`, no DG15): a fixed P-256 key (scalar 0x0101…01)
/// RFC 6979-signs `passive_aa_challenge()`, so the in-circuit secp256r1
/// gadget walks the same succeeding-verification constraint path as a real
/// AA witness — the gadget cannot constrain a FAILING verification, and the
/// acvm solver refuses an off-curve key outright. The scalar is public by
/// construction, which is fine ONLY because this key never enters the DG
/// hash chain (dg_count = 1) and `require_aa = false` is a public input:
/// the triple proves nothing and is never asserted.
fn placeholder_aa_witness() -> ([u8; 32], [u8; 32], [u8; 64]) {
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    let signing = p256::ecdsa::SigningKey::from_slice(&[1u8; 32])
        .expect("fixed placeholder scalar is non-zero and below the P-256 order");
    let point = signing.verifying_key().to_encoded_point(false);
    let x: [u8; 32] = (*point.x().expect("uncompressed P-256 point has x")).into();
    let y: [u8; 32] = (*point.y().expect("uncompressed P-256 point has y")).into();
    let signature: p256::ecdsa::Signature = signing
        .sign_prehash(&passive_aa_challenge())
        .expect("RFC 6979 signing of a fixed digest");
    (x, y, normalize_low_s(&signature.to_bytes().into()))
}

/// SHA-256 of the zero-padded 512-byte DG buffer — mirrors the circuit's
/// `digest(dg_data)` over the full `[u8; MAX_DG_SIZE]` array.
fn padded_dg_hash(content: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 512];
    padded[..content.len()].copy_from_slice(content);
    Sha256::digest(padded).into()
}

/// `openac_core::profile::pack_passport_claims`.
fn pack_passport_claims(claims: &sod::MrzClaims) -> FieldElement {
    let value = (claims.birth_year as u128) * (1u128 << 40)
        + (claims.birth_month as u128) * (1u128 << 32)
        + (claims.birth_day as u128) * (1u128 << 24)
        + (claims.nationality[0] as u128) * 65536
        + (claims.nationality[1] as u128) * 256
        + (claims.nationality[2] as u128);
    FieldElement::from(value)
}

/// `openac_core::predicate::check_age_above` mirror.
fn age_at_least(claims: &sod::MrzClaims, year: u32, month: u32, day: u32, threshold: u32) -> bool {
    if year < claims.birth_year {
        return false;
    }
    let mut age = year - claims.birth_year;
    let birthday_not_yet =
        (month < claims.birth_month) || (month == claims.birth_month && day < claims.birth_day);
    if birthday_not_yet && age > 0 {
        age -= 1;
    }
    age >= threshold
}

fn scope_to_field(link_scope: &str) -> FieldElement {
    let mut hasher = Sha256::new();
    hasher.update(SCOPE_FIELD_DOMAIN);
    hasher.update(link_scope.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    FieldElement::from_be_bytes_reduce(&digest)
}

fn random_field() -> FieldElement {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    FieldElement::from_be_bytes_reduce(&bytes)
}

/// Days-since-epoch → (y, m, d), Howard Hinnant's civil_from_days.
fn utc_today() -> (u32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y } as u32;
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn b64(len: usize, seed: u8) -> String {
        let bytes: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
        STANDARD.encode(bytes)
    }

    fn b64_of(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// Device key: a real P-256 point (the fixture AA key reused as the
    /// device key — tests need any valid point with a controllable signer).
    fn device_key_b64() -> String {
        let point = fixtures::fixture_aa_key()
            .verifying_key()
            .to_encoded_point(false);
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(point.x().unwrap());
        raw.extend_from_slice(point.y().unwrap());
        STANDARD.encode(raw)
    }

    fn fixture_csca_metadata(chip: &fixtures::FixtureChip, index: u32) -> Value {
        json!({
            "schema": "gg.solidarity.passport.csca-metadata.v1",
            "cscas": [
                {
                    "index": index,
                    "tbsSha256Hex": sod::hex_upper(&[0x5A; 32]),
                    "subjectKeyIdentifierHex": sod::hex_upper(&fixtures::FIXTURE_AKI),
                    "subjectNameDerSha256Hex": sod::hex_upper(&chip.csca_name_der_sha256),
                }
            ]
        })
    }

    fn revocation_snapshot(
        chip: &fixtures::FixtureChip,
        revoked_serial20: Option<&[u8; 20]>,
    ) -> Value {
        let entries: Vec<Value> = revoked_serial20
            .map(|serial| {
                vec![json!({
                    "sourceId": "fixture",
                    "crlIndex": 0,
                    "issuerName": "CN=Fixture CSCA,C=TW",
                    "issuerNameSha256": sod::hex_upper(&[0u8; 32]),
                    "issuerNameDerSha256Hex": sod::hex_upper(&chip.csca_name_der_sha256),
                    "authorityKeyIdentifierHex": sod::hex_upper(&fixtures::FIXTURE_AKI),
                    "serialHex": sod::hex_upper(serial),
                    "serial20Hex": sod::hex_upper(serial),
                    "revokedAt": null,
                })]
            })
            .unwrap_or_default();
        let mut snapshot = json!({
            "schema": "gg.solidarity.passport.revocation.v1",
            "sources": [],
            "entries": entries,
        });
        snapshot["cscaMetadata"] = fixture_csca_metadata(chip, 3);
        snapshot
    }

    fn aa_evidence(chip_challenge_seed: u8) -> (String, String, [u8; 32]) {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let rnd8: [u8; 8] = core::array::from_fn(|i| chip_challenge_seed.wrapping_add(i as u8));
        let digest: [u8; 32] = Sha256::digest(rnd8).into();
        let signature: p256::ecdsa::Signature = fixtures::fixture_aa_key()
            .sign_prehash(&digest)
            .expect("AA sign");
        let raw: [u8; 64] = signature.to_bytes().into();
        (STANDARD.encode(digest), STANDARD.encode(raw), digest)
    }

    fn fixture_request(require_aa: bool) -> Value {
        let chip = fixtures::fixture_chip();
        fixture_request_for_chip(chip, require_aa)
    }

    fn fixture_request_for_chip(chip: fixtures::FixtureChip, require_aa: bool) -> Value {
        let (challenge_b64, signature_b64, _) = aa_evidence(0x55);
        // Evidence is attached regardless of require_aa — a real reader
        // produces it whenever the chip supports AA, and a chain-bound DG15
        // without evidence fails closed (the gadget cannot constrain a
        // failing verification). Tests for that path remove "activeAuth".
        json!({
            "schema": REQUEST_SCHEMA,
            "passportNoirVersion": PASSPORT_NOIR_VERSION,
            "passiveAuthValid": true,
            "dataGroups": {
                "sod": b64_of(&chip.sod),
                "dg1": b64_of(&chip.dg1),
                "dg15": b64_of(&chip.dg15),
            },
            "revocationSnapshot": revocation_snapshot(&chip, None),
            "devicePublicKeyRawB64": device_key_b64(),
            "nonceHashB64": b64(32, 5),
            "linkScope": "airmeishi-passport-v3",
            "requireAA": require_aa,
            "activeAuth": {
                "challengeB64": challenge_b64,
                "signatureRawB64": signature_b64,
            },
        })
    }

    /// The passive-only AA challenge as the decimal byte strings the input
    /// map carries — and a guard that it stays non-zero (z = 0 breaks the
    /// barretenberg ECDSA gadget; see `passive_aa_challenge`).
    fn passive_challenge_strings() -> Vec<String> {
        let challenge = passive_aa_challenge();
        assert!(challenge.iter().any(|b| *b != 0));
        challenge.iter().map(|b| b.to_string()).collect()
    }

    fn build_fixture(request: &Value) -> Value {
        let result = build_open_ac_v3_witness_bundle_with_keys(
            &request.to_string(),
            fixtures::fixture_csca_key().clone(),
            fixtures::fixture_dsc_key().clone(),
        )
        .expect("builder returns a result envelope");
        serde_json::from_str(&result).expect("result is JSON")
    }

    fn reason(result: &Value) -> &str {
        result["reason"].as_str().unwrap_or_default()
    }

    // ── Shape-gate reasons (legacy contract) ──

    #[test]
    fn witness_builder_rejects_malformed_json() {
        let err = build_open_ac_v3_witness_bundle("{".to_string()).unwrap_err();
        assert!(err.to_string().contains("invalid witness request JSON"));
    }

    #[test]
    fn witness_builder_reports_missing_active_auth_when_required() {
        let mut request = fixture_request(true);
        request.as_object_mut().unwrap().remove("activeAuth");
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "missing-active-auth-witness");
    }

    #[test]
    fn witness_builder_reports_invalid_device_public_key() {
        let mut request = fixture_request(false);
        request["devicePublicKeyRawB64"] = json!(b64(63, 4));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "invalid-device-public-key");
    }

    #[test]
    fn witness_builder_rejects_off_curve_device_key() {
        let mut request = fixture_request(false);
        request["devicePublicKeyRawB64"] = json!(b64(64, 4));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "invalid-device-public-key");
    }

    #[test]
    fn witness_builder_reports_passive_auth_failure() {
        let mut request = fixture_request(false);
        request["passiveAuthValid"] = json!(false);
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "passive-auth-failed");
    }

    // ── Deep-verification reasons ──

    #[test]
    fn witness_builder_reports_invalid_sod_for_garbage_bytes() {
        let mut request = fixture_request(false);
        request["dataGroups"]["sod"] = json!(b64(64, 1));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "invalid-sod");
    }

    #[test]
    fn witness_builder_reports_dg_hash_mismatch_for_tampered_dg1() {
        let chip = fixtures::fixture_chip();
        let mut dg1 = chip.dg1.clone();
        let last = dg1.len() - 1;
        dg1[last] ^= 0xFF;
        let mut request = fixture_request(false);
        request["dataGroups"]["dg1"] = json!(b64_of(&dg1));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "sod-dg-hash-mismatch");
    }

    #[test]
    fn witness_builder_reports_missing_csca_metadata() {
        let mut request = fixture_request(false);
        request["revocationSnapshot"]
            .as_object_mut()
            .unwrap()
            .remove("cscaMetadata");
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "missing-csca-metadata");
    }

    #[test]
    fn witness_builder_reports_csca_not_in_masterlist() {
        let mut request = fixture_request(false);
        request["revocationSnapshot"]["cscaMetadata"]["cscas"][0]["subjectKeyIdentifierHex"] =
            json!(sod::hex_upper(&[0xEE; 20]));
        request["revocationSnapshot"]["cscaMetadata"]["cscas"][0]["subjectNameDerSha256Hex"] =
            json!(sod::hex_upper(&[0xEE; 32]));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "csca-not-in-masterlist");
    }

    #[test]
    fn witness_builder_reports_revoked_dsc() {
        let chip = fixtures::fixture_chip();
        let mut serial20 = [0u8; 20];
        serial20[15..].copy_from_slice(&fixtures::FIXTURE_DSC_SERIAL);
        let mut request = fixture_request(false);
        request["revocationSnapshot"] = revocation_snapshot(&chip, Some(&serial20));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "dsc-revoked");
    }

    #[test]
    fn witness_builder_rejects_aa_signature_for_wrong_challenge() {
        let mut request = fixture_request(true);
        let (_, _, _) = aa_evidence(0x55);
        request["activeAuth"]["challengeB64"] = json!(b64(32, 9));
        let result = build_fixture(&request);
        assert_eq!(reason(&result), "invalid-active-auth-signature");
    }

    // ── Ready path ──

    #[test]
    fn witness_builder_produces_complete_bundle_for_fixture_chip() {
        let request = fixture_request(true);
        let result = build_fixture(&request);
        assert_eq!(result["ready"], json!(true), "unexpected: {result}");

        let bundle: Value =
            serde_json::from_str(result["bundleJson"].as_str().expect("bundleJson"))
                .expect("bundle parses");
        for key in [
            "dscChainInputsJson",
            "passportAdapterInputsJson",
            "openAcShowInputsJson",
        ] {
            let inputs: Value =
                serde_json::from_str(bundle[key].as_str().expect("inputs json")).expect("parses");
            assert!(inputs.is_object(), "{key} must be a map");
        }

        // dsc_chain ↔ passport_adapter linking id must match.
        let dsc_chain: BTreeMap<String, Vec<String>> =
            serde_json::from_str(bundle["dscChainInputsJson"].as_str().unwrap()).unwrap();
        let adapter: BTreeMap<String, Vec<String>> =
            serde_json::from_str(bundle["passportAdapterInputsJson"].as_str().unwrap()).unwrap();
        assert_eq!(dsc_chain["out_dsc_id"], adapter["in_dsc_id"]);
        assert_eq!(dsc_chain["dsc_tbs"].len(), 512);
        assert_eq!(adapter["dg_contents"].len(), 1024);
        assert_eq!(adapter["aa_challenge"].len(), 32);

        // Commitment coordinates must agree across adapter and show.
        let show: BTreeMap<String, Vec<String>> =
            serde_json::from_str(bundle["openAcShowInputsJson"].as_str().unwrap()).unwrap();
        assert_eq!(adapter["out_commitment_x"], show["out_commitment_x"]);
        assert_eq!(adapter["out_commitment_y"], show["out_commitment_y"]);
        assert_eq!(show["signature"].len(), 64);
        assert_eq!(show["nonce_hash"].len(), 32);
        // TWN nationality disclosed.
        assert_eq!(show["out_nationality"], vec!["84", "87", "78"]);
        // Born 1990 → over 18 today.
        assert_eq!(show["out_is_older"], vec!["1"]);
    }

    // ── End-to-end: the bundle must satisfy the real circuits ──

    /// The definitive check: witnesses from a fixture chip read must prove
    /// AND verify under the shipped 0.3.0 circuit artifacts for all three
    /// circuits, with the device signature bound the way the app binds it.
    /// Heavy (3 UltraHonk proofs) — run explicitly:
    ///   cargo test --release openac_v3_e2e_proofs -- --ignored
    #[test]
    #[ignore = "generates 3 real proofs; run with --ignored (release recommended)"]
    fn openac_v3_e2e_proofs_generate_and_verify() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use std::path::PathBuf;

        let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let circuit = |name: &str| {
            let path = vectors.join(format!("test-vectors/noir/{name}.json"));
            assert!(path.exists(), "missing circuit artifact {path:?}");
            path.to_string_lossy().to_string()
        };
        // Single merged SRS (sized to the largest of the three circuits) —
        // the app bundles exactly this one blob and points every circuit at
        // it. Proving all three against it exercises the prefix-sharing the
        // consolidation relies on.
        let srs = |_name: &str| {
            let path = vectors.join("test-vectors/srs/passport.srs.bin");
            assert!(
                path.exists(),
                "missing merged SRS {path:?} — run `make gen-srs`"
            );
            Some(path.to_string_lossy().to_string())
        };

        let request = fixture_request(true);
        let result = build_fixture(&request);
        assert_eq!(result["ready"], json!(true), "unexpected: {result}");
        let bundle: Value = serde_json::from_str(result["bundleJson"].as_str().unwrap()).unwrap();

        let parse_inputs = |key: &str| -> std::collections::HashMap<String, Vec<String>> {
            serde_json::from_str(bundle[key].as_str().unwrap()).unwrap()
        };

        let dsc_chain = parse_inputs("dscChainInputsJson");
        let adapter = parse_inputs("passportAdapterInputsJson");
        let mut show = parse_inputs("openAcShowInputsJson");

        // Bind the device signature over nonce_hash exactly like the app's
        // bindPassportOpenAcV3DeviceSignature step.
        let nonce_hash: Vec<u8> = show["nonce_hash"]
            .iter()
            .map(|s| s.parse::<u8>().expect("nonce byte"))
            .collect();
        let nonce_hash: [u8; 32] = nonce_hash.as_slice().try_into().unwrap();
        let signature: p256::ecdsa::Signature = fixtures::fixture_aa_key()
            .sign_prehash(&nonce_hash)
            .expect("device sign");
        let raw: [u8; 64] = normalize_low_s(&signature.to_bytes().into());
        show.insert(
            "signature".into(),
            raw.iter().map(|b| b.to_string()).collect(),
        );

        for (name, inputs) in [
            ("dsc_chain", dsc_chain),
            ("passport_adapter", adapter),
            ("openac_show", show),
        ] {
            let proof = crate::noir::generate_noir_proof(circuit(name), srs(name), inputs)
                .unwrap_or_else(|e| panic!("{name} proof generation failed: {e}"));
            let verified = crate::noir::verify_noir_proof(proof.proof.clone(), proof.vk.clone())
                .unwrap_or_else(|e| panic!("{name} verification errored: {e}"));
            assert!(verified, "{name} proof must verify");
        }
    }

    /// Passive-only regression (build 28 field report): a chip without DG15
    /// must produce a passport_adapter witness the prover can SOLVE. The
    /// zero-filled AA key slot used to abort UltraHonk witness solving with
    /// "Failed to solve blackbox function: ecdsa_secp256k1, reason: Invalid
    /// public key provided for ECDSA verification" — the r1 blackbox under
    /// the mislabeled upstream error. Heavy (1 UltraHonk proof):
    ///   cargo test --release openac_v3_e2e_passive -- --ignored
    #[test]
    #[ignore = "generates a real proof; run with --ignored (release recommended)"]
    fn openac_v3_e2e_passive_only_passport_adapter_proves() {
        use std::path::PathBuf;

        let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let circuit_path = vectors.join("test-vectors/noir/passport_adapter.json");
        assert!(
            circuit_path.exists(),
            "missing circuit artifact {circuit_path:?}"
        );
        let srs_path = vectors.join("test-vectors/srs/passport.srs.bin");
        assert!(
            srs_path.exists(),
            "missing merged SRS {srs_path:?} — run `make gen-srs`"
        );

        let mut request = fixture_request_for_chip(fixtures::fixture_chip_without_dg15(), false);
        request["dataGroups"]
            .as_object_mut()
            .unwrap()
            .remove("dg15");
        request.as_object_mut().unwrap().remove("activeAuth");
        let result = build_fixture(&request);
        assert_eq!(result["ready"], json!(true), "unexpected: {result}");
        let bundle: Value = serde_json::from_str(result["bundleJson"].as_str().unwrap()).unwrap();
        let adapter: std::collections::HashMap<String, Vec<String>> =
            serde_json::from_str(bundle["passportAdapterInputsJson"].as_str().unwrap()).unwrap();

        let proof = crate::noir::generate_noir_proof(
            circuit_path.to_string_lossy().to_string(),
            Some(srs_path.to_string_lossy().to_string()),
            adapter,
        )
        .unwrap_or_else(|e| panic!("passive-only passport_adapter proof generation failed: {e}"));
        let verified = crate::noir::verify_noir_proof(proof.proof.clone(), proof.vk.clone())
            .unwrap_or_else(|e| panic!("passive-only verification errored: {e}"));
        assert!(verified, "passive-only passport_adapter proof must verify");
    }

    #[test]
    fn witness_bundle_with_dg15_keeps_real_evidence_when_aa_not_required() {
        // DG15 present + AA evidence attached, but the verifier policy does
        // not require AA: the witness keeps the REAL pre-verified triple
        // (the gadget still needs a verifying triple) with require_aa = 0.
        let request = fixture_request(false);
        let result = build_fixture(&request);
        assert_eq!(result["ready"], json!(true), "unexpected: {result}");
        let bundle: Value = serde_json::from_str(result["bundleJson"].as_str().unwrap()).unwrap();
        let adapter: BTreeMap<String, Vec<String>> =
            serde_json::from_str(bundle["passportAdapterInputsJson"].as_str().unwrap()).unwrap();
        assert_eq!(adapter["require_aa"], vec!["0"]);
        let (_, _, challenge) = aa_evidence(0x55);
        let challenge_strings: Vec<String> = challenge.iter().map(|b| b.to_string()).collect();
        assert_eq!(adapter["aa_challenge"], challenge_strings);
    }

    #[test]
    fn witness_builder_fails_closed_when_dg15_present_without_aa_evidence() {
        // A chain-bound DG15 key with no chip signature cannot yield a
        // verifying AA triple (the barretenberg gadget cannot constrain a
        // failing verification), so the builder must fail closed instead of
        // emitting a witness whose proof never verifies.
        let mut request = fixture_request(false);
        request.as_object_mut().unwrap().remove("activeAuth");
        let result = build_fixture(&request);
        assert_eq!(result["ready"], json!(false), "unexpected: {result}");
        assert_eq!(reason(&result), "missing-active-auth-witness");
    }

    #[test]
    fn witness_builder_accepts_dg1_only_passive_path_when_aa_not_required() {
        let mut request = fixture_request_for_chip(fixtures::fixture_chip_without_dg15(), false);
        request["dataGroups"]
            .as_object_mut()
            .unwrap()
            .remove("dg15");
        request.as_object_mut().unwrap().remove("activeAuth");
        let result = build_fixture(&request);
        assert_eq!(result["ready"], json!(true), "unexpected: {result}");

        let bundle: Value = serde_json::from_str(result["bundleJson"].as_str().unwrap()).unwrap();
        let adapter: BTreeMap<String, Vec<String>> =
            serde_json::from_str(bundle["passportAdapterInputsJson"].as_str().unwrap()).unwrap();
        assert_eq!(adapter["dg_count"], vec!["1"]);
        assert_eq!(adapter["require_aa"], vec!["0"]);
        assert_eq!(adapter["aa_challenge"], passive_challenge_strings());

        // The circuit always evaluates the secp256r1 blackbox on the AA slot
        // even though require_aa = false leaves the result unasserted, and
        // only a SUCCEEDING verification is constrainable: an off-curve key
        // — (0,0) in particular — aborts witness solving with "Invalid
        // public key provided for ECDSA verification" (build 28 field
        // report, surfaced under the misleading upstream label
        // `ecdsa_secp256k1`), and a non-verifying triple yields a proof that
        // fails verification. The placeholder triple must therefore VERIFY.
        let dg_contents: Vec<u8> = adapter["dg_contents"]
            .iter()
            .map(|s| s.parse::<u8>().expect("dg byte"))
            .collect();
        let aa_pk_x: [u8; 32] = dg_contents[512..544].try_into().expect("aa x");
        let aa_pk_y: [u8; 32] = dg_contents[544..576].try_into().expect("aa y");
        let placeholder_key = p256_verifying_key(&aa_pk_x, &aa_pk_y)
            .expect("passive-only AA placeholder key must be on the P-256 curve");
        let aa_signature: Vec<u8> = adapter["aa_signature"]
            .iter()
            .map(|s| s.parse::<u8>().expect("sig byte"))
            .collect();
        let aa_signature: [u8; 64] = aa_signature.as_slice().try_into().expect("aa sig");
        assert!(
            p256_verify_prehash(&placeholder_key, &passive_aa_challenge(), &aa_signature),
            "passive-only AA placeholder triple must verify under its own key"
        );
    }
}
