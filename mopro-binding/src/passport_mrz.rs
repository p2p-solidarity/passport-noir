//! passport-noir 0.5.0 — MRZ endorsement + device binding
//! (`circuits/passport_mrz`).
//!
//! Prover side: `build_passport_mrz_witness` turns the chip's raw EF.SOD +
//! DG1 and a device signature over the verifier's challenge into the
//! circuit's inputs, failing closed (with a reason) on anything the circuit
//! does not support. Verifier side: `verify_passport_mrz` checks the DSC
//! certificate against a PINNED CSCA list, that the proof's public DSC modulus
//! is that certificate's key, that the public request matches, and the proof.
//!
//! What a verifying proof means: a DSC issued by one of the pinned CSCAs
//! signed an LDSSecurityObject containing this MRZ's hash, and whoever holds
//! the device key signed the challenge. It does NOT mean the chip was present
//! (no Active Authentication) or that the presenter is the passport holder.

pub(crate) mod cms;
#[cfg(test)]
pub(crate) mod fixtures;

use std::collections::HashMap;

use noir_rs::acir::{AcirField, FieldElement};
use num_bigint_dig::BigUint;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

use crate::MoproError;

pub const PASSPORT_NOIR_VERSION: &str = "0.5.0";

const DG1_LEN: usize = 93;
const DG1_HEADER: [u8; 5] = [0x61, 0x5B, 0x5F, 0x1F, 0x58];
const MAX_ECONTENT: usize = 768;
const MAX_SIGNED_ATTRS: usize = 256;
const RSA_LIMB_COUNT: usize = 18;
const RSA_MODULUS_BITS: usize = 2048;
/// noir-bignum v0.9.2 `BARRETT_REDUCTION_OVERFLOW_BITS` (paramgen 0.1.5 still says 4).
const BARRETT_REDUCTION_OVERFLOW_BITS: usize = 6;
const DG1_HASH_PREFIX: [u8; 7] = [0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
const MESSAGE_DIGEST_PREFIX: [u8; 17] = [
    0x30, 0x2F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04,
    0x20,
];
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
/// Domain separator for mapping a scope string to a Field ("" = no scope).
const SCOPE_FIELD_DOMAIN: &[u8] = b"passport-noir.mrz.scope.v1";
/// dsc_modulus_limbs, challenge, scope, today, min_age, disclose_nationality,
/// then the return values age_ok, nationality[3], device_tag, nullifier.
const PUBLIC_INPUT_COUNT: usize = RSA_LIMB_COUNT + 32 + 4 + 1 + 3 + 2;

/// What the verifier asks for; the prover proves exactly this.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PassportMrzRequest {
    /// 32 bytes the device key signs (verifier-chosen, fresh per request).
    pub challenge: Vec<u8>,
    /// Pseudonym scope for the device tag and nullifier; "" = no nullifier.
    pub scope: String,
    /// UTC date as YYYYMMDD.
    pub today: u32,
    /// 0 = do not disclose age.
    pub min_age: u32,
    pub disclose_nationality: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PassportMrzWitness {
    /// Circuit inputs (decimal strings) for `generate_noir_proof`.
    pub inputs: HashMap<String, Vec<String>>,
    /// The DSC certificate DER; ships next to the proof for the verifier.
    pub dsc_certificate: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PassportMrzOutputs {
    /// False when `min_age` was 0 (not disclosed).
    pub age_ok: bool,
    /// ICAO nationality code, or "" when not disclosed.
    pub nationality: String,
    /// Per-scope pseudonym of the device key (hex Field).
    pub device_tag: String,
    /// Per-scope passport nullifier (hex Field), zero without a scope.
    pub nullifier: String,
    /// Country (C=) of the pinned CSCA that issued the DSC.
    pub issuer_country: String,
}

/// Every refusal, as a stable reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MrzError {
    #[error("unsupported-dg1")]
    UnsupportedDg1,
    #[error("invalid-sod")]
    InvalidSod,
    #[error("unsupported-cms-digest")]
    UnsupportedCmsDigest,
    #[error("unsupported-dsc-signature")]
    UnsupportedDscSignature,
    #[error("unsupported-dsc-key")]
    UnsupportedDscKey,
    #[error("sod-too-large")]
    SodTooLarge,
    #[error("dsc-signature-invalid")]
    DscSignatureInvalid,
    #[error("message-digest-mismatch")]
    MessageDigestMismatch,
    #[error("dg1-hash-mismatch")]
    Dg1HashMismatch,
    #[error("invalid-request")]
    InvalidRequest,
    #[error("device-signature-invalid")]
    DeviceSignatureInvalid,
    #[error("invalid-dsc-certificate")]
    InvalidDscCertificate,
    #[error("dsc-not-issued-by-pinned-csca")]
    DscNotIssuedByPinnedCsca,
    #[error("certificate-not-valid-now")]
    CertificateNotValidNow,
    #[error("dsc-revoked")]
    DscRevoked,
    #[error("dsc-modulus-mismatch")]
    DscModulusMismatch,
    #[error("malformed-proof")]
    MalformedProof,
    #[error("request-mismatch")]
    RequestMismatch,
    #[error("proof-invalid")]
    ProofInvalid,
}

impl From<cms::InvalidSod> for MrzError {
    fn from(_: cms::InvalidSod) -> Self {
        MrzError::InvalidSod
    }
}

// ---------------------------------------------------------------------------
// Shared encoding
// ---------------------------------------------------------------------------

fn limbs_120(value: &BigUint) -> [FieldElement; RSA_LIMB_COUNT] {
    let limbs = noir_bignum_paramgen::split_into_120_bit_limbs(value, RSA_MODULUS_BITS);
    let mut out = [FieldElement::zero(); RSA_LIMB_COUNT];
    for (i, limb) in limbs.iter().enumerate().take(RSA_LIMB_COUNT) {
        out[i] = FieldElement::from_be_bytes_reduce(&limb.to_bytes_be());
    }
    out
}

/// floor(2^{2 * 2048 + 6} / modulus), the circuit's `BigNumParams<18, 2048>` redc.
fn redc_limbs_120(modulus: &BigUint) -> [FieldElement; RSA_LIMB_COUNT] {
    let exponent = 2 * RSA_MODULUS_BITS + BARRETT_REDUCTION_OVERFLOW_BITS;
    limbs_120(&((BigUint::from(1u8) << exponent) / modulus))
}

fn scope_field(scope: &str) -> FieldElement {
    if scope.is_empty() {
        return FieldElement::zero();
    }
    let digest = Sha256::new()
        .chain_update(SCOPE_FIELD_DOMAIN)
        .chain_update(scope.as_bytes())
        .finalize();
    FieldElement::from_be_bytes_reduce(&digest)
}

fn decimal(field: FieldElement) -> String {
    num_bigint::BigUint::from_bytes_be(&field.to_be_bytes()).to_str_radix(10)
}

fn byte_strings(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| b.to_string()).collect()
}

fn padded(bytes: &[u8], len: usize) -> Vec<String> {
    let mut out = byte_strings(bytes);
    out.resize(len, "0".into());
    out
}

/// Exactly one occurrence of `prefix ‖ value` in `haystack`; returns the
/// offset of `value`.
fn unique_tagged_hash(haystack: &[u8], prefix: &[u8], value: &[u8; 32]) -> Option<usize> {
    let mut found = None;
    for at in prefix.len()..=haystack.len().saturating_sub(32) {
        if &haystack[at - prefix.len()..at] == prefix && &haystack[at..at + 32] == value {
            if found.is_some() {
                return None;
            }
            found = Some(at);
        }
    }
    found
}

fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>, MrzError> {
    match X509Certificate::from_der(der) {
        Ok((rest, cert)) if rest.is_empty() => Ok(cert),
        _ => Err(MrzError::InvalidDscCertificate),
    }
}

/// The DSC's RSA-2048 / e = 65537 public key (the only DSC the circuit verifies).
fn dsc_rsa_key(cert: &X509Certificate<'_>) -> Result<RsaPublicKey, MrzError> {
    use x509_parser::public_key::PublicKey;
    let Ok(PublicKey::RSA(key)) = cert.public_key().parsed() else {
        return Err(MrzError::UnsupportedDscKey);
    };
    let n = rsa::BigUint::from_bytes_be(key.modulus);
    let e = rsa::BigUint::from_bytes_be(key.exponent);
    if n.bits() != RSA_MODULUS_BITS || e != rsa::BigUint::from(65_537u32) {
        return Err(MrzError::UnsupportedDscKey);
    }
    RsaPublicKey::new(n, e).map_err(|_| MrzError::UnsupportedDscKey)
}

fn modulus_of(key: &RsaPublicKey) -> BigUint {
    BigUint::from_bytes_be(&key.n().to_bytes_be())
}

// ---------------------------------------------------------------------------
// Prover side
// ---------------------------------------------------------------------------

fn low_s(signature: &p256::ecdsa::Signature) -> [u8; 64] {
    // Barretenberg's secp256r1 blackbox only accepts low-S.
    signature
        .normalize_s()
        .unwrap_or(*signature)
        .to_bytes()
        .into()
}

fn witness(
    sod: &[u8],
    dg1: &[u8],
    device_public_key: &[u8],
    device_signature: &[u8],
    request: &PassportMrzRequest,
) -> Result<PassportMrzWitness, MrzError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    if dg1.len() != DG1_LEN || dg1[..5] != DG1_HEADER {
        return Err(MrzError::UnsupportedDg1);
    }
    let parts = cms::signed_parts(sod)?;
    if parts.digest_oid != OID_SHA256 {
        return Err(MrzError::UnsupportedCmsDigest);
    }
    if parts.signature_oid != OID_SHA256_WITH_RSA && parts.signature_oid != OID_RSA_ENCRYPTION {
        return Err(MrzError::UnsupportedDscSignature);
    }
    let dsc = parse_certificate(&parts.dsc_der)?;
    let dsc_key = dsc_rsa_key(&dsc)?;
    if parts.econtent.len() > MAX_ECONTENT || parts.signed_attrs.len() > MAX_SIGNED_ATTRS {
        return Err(MrzError::SodTooLarge);
    }
    let attrs_hash = Sha256::digest(&parts.signed_attrs);
    dsc_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &attrs_hash, &parts.signature)
        .map_err(|_| MrzError::DscSignatureInvalid)?;
    let md_offset = unique_tagged_hash(
        &parts.signed_attrs,
        &MESSAGE_DIGEST_PREFIX,
        &Sha256::digest(&parts.econtent).into(),
    )
    .ok_or(MrzError::MessageDigestMismatch)?;
    let dg1_offset = unique_tagged_hash(
        &parts.econtent,
        &DG1_HASH_PREFIX,
        &Sha256::digest(dg1).into(),
    )
    .ok_or(MrzError::Dg1HashMismatch)?;

    let challenge: [u8; 32] = request
        .challenge
        .as_slice()
        .try_into()
        .map_err(|_| MrzError::InvalidRequest)?;
    if device_public_key.len() != 65 || device_public_key[0] != 0x04 {
        return Err(MrzError::DeviceSignatureInvalid);
    }
    let device_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(device_public_key)
        .map_err(|_| MrzError::DeviceSignatureInvalid)?;
    let signature = p256::ecdsa::Signature::from_slice(device_signature)
        .map_err(|_| MrzError::DeviceSignatureInvalid)?;
    device_key
        .verify_prehash(&challenge, &signature)
        .map_err(|_| MrzError::DeviceSignatureInvalid)?;

    let modulus = modulus_of(&dsc_key);
    let signature_value = BigUint::from_bytes_be(&parts.signature);
    let fields = |f: [FieldElement; RSA_LIMB_COUNT]| f.iter().map(|x| decimal(*x)).collect();
    let mut inputs: HashMap<String, Vec<String>> = HashMap::new();
    let mut put = |name: &str, values: Vec<String>| inputs.insert(name.into(), values);
    put("dg1", byte_strings(dg1));
    put("econtent", padded(&parts.econtent, MAX_ECONTENT));
    put("econtent_len", vec![parts.econtent.len().to_string()]);
    put("dg1_hash_offset", vec![dg1_offset.to_string()]);
    put(
        "signed_attrs",
        padded(&parts.signed_attrs, MAX_SIGNED_ATTRS),
    );
    put(
        "signed_attrs_len",
        vec![parts.signed_attrs.len().to_string()],
    );
    put("message_digest_offset", vec![md_offset.to_string()]);
    put("signature_limbs", fields(limbs_120(&signature_value)));
    put("redc_limbs", fields(redc_limbs_120(&modulus)));
    put("device_pk_x", byte_strings(&device_public_key[1..33]));
    put("device_pk_y", byte_strings(&device_public_key[33..65]));
    put("device_signature", byte_strings(&low_s(&signature)));
    put("dsc_modulus_limbs", fields(limbs_120(&modulus)));
    put("challenge", byte_strings(&challenge));
    put("scope", vec![decimal(scope_field(&request.scope))]);
    put("today", vec![request.today.to_string()]);
    put("min_age", vec![request.min_age.to_string()]);
    put(
        "disclose_nationality",
        vec![u8::from(request.disclose_nationality).to_string()],
    );
    Ok(PassportMrzWitness {
        inputs,
        dsc_certificate: parts.dsc_der,
    })
}

/// Circuit inputs for one presentation. `device_public_key` is the SEC1
/// uncompressed P-256 point (65 bytes); `device_signature` is r ‖ s (64
/// bytes) over `request.challenge` as a prehash.
#[uniffi::export]
pub fn build_passport_mrz_witness(
    sod: Vec<u8>,
    dg1: Vec<u8>,
    device_public_key: Vec<u8>,
    device_signature: Vec<u8>,
    request: PassportMrzRequest,
) -> Result<PassportMrzWitness, MoproError> {
    witness(&sod, &dg1, &device_public_key, &device_signature, &request)
        .map_err(|e| MoproError::InvalidInput(e.to_string()))
}

/// Prove with `passport_mrz.json` and an SRS of exactly the circuit's size.
#[uniffi::export]
pub fn prove_passport_mrz(
    circuit_path: String,
    srs_path: Option<String>,
    inputs: HashMap<String, Vec<String>>,
) -> Result<crate::noir::NoirProofResult, MoproError> {
    crate::noir::generate_noir_proof_exact(&circuit_path, srs_path.as_deref(), inputs)
}

// ---------------------------------------------------------------------------
// Verifier side
// ---------------------------------------------------------------------------

/// The pinned CSCA (one of `cscas`) that issued `dsc`.
fn issuing_csca<'a>(
    dsc: &X509Certificate<'_>,
    cscas: &'a [X509Certificate<'a>],
) -> Option<&'a X509Certificate<'a>> {
    let aki = dsc
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|k| k.0)
            }
            _ => None,
        });
    cscas.iter().find(|csca| {
        let ski = csca
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0),
                _ => None,
            });
        let key_ids_agree = !matches!((aki, ski), (Some(a), Some(s)) if a != s);
        csca.subject().as_raw() == dsc.issuer().as_raw()
            && key_ids_agree
            && verify_issued_by(dsc, csca)
    })
}

/// RSA PKCS#1 v1.5 (SHA-256/384/512) and ECDSA P-256/P-384 via ring; SHA-1
/// and anything else is refused.
fn verify_issued_by(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    const ALLOWED: [&str; 5] = [
        "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12",
        "1.2.840.113549.1.1.13",
        "1.2.840.10045.4.3.2",
        "1.2.840.10045.4.3.3",
    ];
    let alg = cert.signature_algorithm.algorithm.to_id_string();
    ALLOWED.contains(&alg.as_str()) && cert.verify_signature(Some(issuer.public_key())).is_ok()
}

fn country(cert: &X509Certificate<'_>) -> String {
    cert.subject()
        .iter_country()
        .next()
        .and_then(|c| c.as_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn field_hex(field: &FieldElement) -> String {
    field
        .to_be_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The public inputs of a mopro proof: a 4-byte BE count, then 32-byte fields.
fn public_inputs(proof: &[u8]) -> Result<Vec<FieldElement>, MrzError> {
    let count = u32::from_be_bytes(
        proof
            .get(..4)
            .ok_or(MrzError::MalformedProof)?
            .try_into()
            .unwrap(),
    );
    if count as usize != PUBLIC_INPUT_COUNT || proof.len() < 4 + PUBLIC_INPUT_COUNT * 32 {
        return Err(MrzError::MalformedProof);
    }
    Ok(proof[4..4 + PUBLIC_INPUT_COUNT * 32]
        .chunks(32)
        .map(FieldElement::from_be_bytes_reduce)
        .collect())
}

pub struct TrustAnchors<'a> {
    pub csca_certificates: &'a [Vec<u8>],
    /// DSC serial numbers (big-endian, no sign byte) revoked by their CSCA's CRL.
    pub revoked_dsc_serials: &'a [Vec<u8>],
}

fn check_certificates(
    dsc_der: &[u8],
    trust: &TrustAnchors<'_>,
    now_unix: i64,
) -> Result<(BigUint, String), MrzError> {
    let dsc = parse_certificate(dsc_der)?;
    let cscas: Vec<X509Certificate<'_>> = trust
        .csca_certificates
        .iter()
        .filter_map(|der| parse_certificate(der).ok())
        .collect();
    let csca = issuing_csca(&dsc, &cscas).ok_or(MrzError::DscNotIssuedByPinnedCsca)?;
    let valid = |c: &X509Certificate<'_>| {
        c.validity().not_before.timestamp() <= now_unix
            && now_unix <= c.validity().not_after.timestamp()
    };
    if !valid(&dsc) || !valid(csca) {
        return Err(MrzError::CertificateNotValidNow);
    }
    let serial = dsc.tbs_certificate.serial.to_bytes_be();
    let serial: Vec<u8> = serial.into_iter().skip_while(|b| *b == 0).collect();
    if trust.revoked_dsc_serials.iter().any(|r| {
        r.iter()
            .copied()
            .skip_while(|b| *b == 0)
            .eq(serial.iter().copied())
    }) {
        return Err(MrzError::DscRevoked);
    }
    Ok((modulus_of(&dsc_rsa_key(&dsc)?), country(csca)))
}

fn expected_request_inputs(request: &PassportMrzRequest) -> Result<Vec<FieldElement>, MrzError> {
    if request.challenge.len() != 32 {
        return Err(MrzError::InvalidRequest);
    }
    let mut out: Vec<FieldElement> = request
        .challenge
        .iter()
        .map(|b| FieldElement::from(*b as u128))
        .collect();
    out.push(scope_field(&request.scope));
    out.push(FieldElement::from(request.today as u128));
    out.push(FieldElement::from(request.min_age as u128));
    out.push(FieldElement::from(u128::from(request.disclose_nationality)));
    Ok(out)
}

/// Everything except the barretenberg check, so it is testable without SRS.
fn check_presentation(
    proof: &[u8],
    dsc_der: &[u8],
    trust: &TrustAnchors<'_>,
    request: &PassportMrzRequest,
    now_unix: i64,
) -> Result<PassportMrzOutputs, MrzError> {
    let (modulus, issuer_country) = check_certificates(dsc_der, trust, now_unix)?;
    let public = public_inputs(proof)?;
    if public[..RSA_LIMB_COUNT] != limbs_120(&modulus) {
        return Err(MrzError::DscModulusMismatch);
    }
    let request_end = RSA_LIMB_COUNT + 36;
    if public[RSA_LIMB_COUNT..request_end] != expected_request_inputs(request)? {
        return Err(MrzError::RequestMismatch);
    }
    let out = &public[request_end..];
    let as_bool = |f: &FieldElement| {
        if f.is_zero() {
            Some(false)
        } else if f.is_one() {
            Some(true)
        } else {
            None
        }
    };
    let age_ok = as_bool(&out[0]).ok_or(MrzError::MalformedProof)?;
    let nationality: Vec<u8> = out[1..4].iter().map(|f| f.to_u128() as u8).collect();
    Ok(PassportMrzOutputs {
        age_ok,
        nationality: String::from_utf8_lossy(&nationality)
            .trim_end_matches('\0')
            .to_string(),
        device_tag: field_hex(&out[4]),
        nullifier: field_hex(&out[5]),
        issuer_country,
    })
}

/// Verify one presentation. `circuit_path` is the released `passport_mrz.json`
/// (the verification key is derived from it, never taken from the prover).
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn verify_passport_mrz(
    circuit_path: String,
    srs_path: Option<String>,
    proof: Vec<u8>,
    dsc_certificate: Vec<u8>,
    csca_certificates: Vec<Vec<u8>>,
    revoked_dsc_serials: Vec<Vec<u8>>,
    request: PassportMrzRequest,
    now_unix: i64,
) -> Result<PassportMrzOutputs, MoproError> {
    let trust = TrustAnchors {
        csca_certificates: &csca_certificates,
        revoked_dsc_serials: &revoked_dsc_serials,
    };
    let outputs = check_presentation(&proof, &dsc_certificate, &trust, &request, now_unix)
        .map_err(|e| MoproError::VerificationError(e.to_string()))?;
    let vk = crate::noir::get_noir_verification_key_exact(&circuit_path, srs_path.as_deref())?;
    if !crate::noir::verify_noir_proof(proof, vk)? {
        return Err(MoproError::VerificationError(
            MrzError::ProofInvalid.to_string(),
        ));
    }
    Ok(outputs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Failure modes, listed before the code:
//   builder   non-TD3 DG1; SOD not CMS; DSC signature over SignedAttributes
//             invalid; messageDigest != H(eContent); DG1 hash absent from
//             eContent; device signature over another challenge; DSC not
//             RSA-2048/65537.
//   verifier  DSC chained to no pinned CSCA (same issuer name, other key — the
//             <= 0.4.0 forgery); empty trust list; DSC or CSCA outside its
//             validity; revoked DSC serial; proof's DSC modulus is not the
//             certificate's; public request (challenge, scope, date, age,
//             nationality flag) differs from the verifier's; wrong public-input
//             count; a tampered public output (caught by the proof itself).
//   circuit   a DG1 that is not in the signed eContent cannot be proven.

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    const NOW: i64 = 1_793_318_400; // 2026-10-30T00:00Z
    const AFTER_DSC_EXPIRY: i64 = 2_114_380_800; // 2037-01-01

    fn request() -> PassportMrzRequest {
        PassportMrzRequest {
            challenge: Sha256::digest(b"verifier challenge").to_vec(),
            scope: "creds.passport.nullifier.v1".into(),
            today: 20261030,
            min_age: 18,
            disclose_nationality: true,
        }
    }

    fn device() -> (Vec<u8>, Vec<u8>) {
        let key = fixtures::fixture_device_key();
        let point = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let signature: p256::ecdsa::Signature = key.sign_prehash(&request().challenge).unwrap();
        (point, signature.to_bytes().to_vec())
    }

    fn build(chip: &fixtures::FixtureChip) -> Result<PassportMrzWitness, MrzError> {
        let (pk, sig) = device();
        witness(&chip.sod, &chip.dg1, &pk, &sig, &request())
    }

    fn trust_anchors(cscas: &[Vec<u8>]) -> TrustAnchors<'_> {
        TrustAnchors {
            csca_certificates: cscas,
            revoked_dsc_serials: &[],
        }
    }

    /// Proof-shaped bytes carrying `w`'s public inputs (no barretenberg proof):
    /// enough for everything `check_presentation` checks.
    fn fake_proof(w: &PassportMrzWitness) -> Vec<u8> {
        let mut public: Vec<String> = Vec::new();
        for name in [
            "dsc_modulus_limbs",
            "challenge",
            "scope",
            "today",
            "min_age",
            "disclose_nationality",
        ] {
            public.extend(w.inputs[name].iter().cloned());
        }
        public.extend(["1", "84", "87", "78", "5", "7"].map(String::from));
        let mut out = (public.len() as u32).to_be_bytes().to_vec();
        for value in public {
            out.extend(FieldElement::try_from_str(&value).unwrap().to_be_bytes());
        }
        out.extend([0u8; 64]);
        out
    }

    #[test]
    fn builds_inputs_for_a_genuinely_signed_chip() {
        let chip = fixtures::signed_chip();
        let w = build(&chip).expect("witness");
        assert_eq!(w.dsc_certificate, chip.dsc_cert);
        assert_eq!(w.inputs["econtent"].len(), MAX_ECONTENT);
        assert_eq!(w.inputs["signed_attrs"].len(), MAX_SIGNED_ATTRS);
        assert_eq!(w.inputs["dg1"].len(), DG1_LEN);
    }

    #[test]
    fn refuses_chip_data_the_dsc_did_not_sign() {
        let chip = fixtures::signed_chip();
        let mut dg1 = chip.dg1.clone();
        dg1[60] = b'X'; // nationality byte
        let (pk, sig) = device();
        assert_eq!(
            witness(&chip.sod, &dg1, &pk, &sig, &request()).unwrap_err(),
            MrzError::Dg1HashMismatch
        );

        let mut short = chip.dg1.clone();
        short.pop();
        assert_eq!(
            witness(&chip.sod, &short, &pk, &sig, &request()).unwrap_err(),
            MrzError::UnsupportedDg1
        );
        assert_eq!(
            witness(&chip.dg1, &chip.dg1, &pk, &sig, &request()).unwrap_err(),
            MrzError::InvalidSod
        );
    }

    #[test]
    fn refuses_a_sod_whose_signature_or_digest_does_not_hold() {
        use fixtures::*;
        let dg1 = fixture_dg1();
        let econtent = lds_security_object(&dg1);
        let attrs = signed_attrs_content(&econtent);
        let dsc = dsc_cert(fixture_csca_key());
        let (pk, sig) = device();

        // Signed by a key that is not the DSC's.
        let wrong = rsa_sha256_sign(fixture_csca_key(), &der_set(&[attrs.clone()]));
        let forged = sod(&econtent, &attrs, &wrong, &dsc);
        assert_eq!(
            witness(&forged, &dg1, &pk, &sig, &request()).unwrap_err(),
            MrzError::DscSignatureInvalid
        );

        // Genuine signature, but over the digest of another eContent.
        let other = lds_security_object(b"another DG1");
        let other_attrs = signed_attrs_content(&other);
        let signature = rsa_sha256_sign(fixture_dsc_key(), &der_set(&[other_attrs.clone()]));
        let swapped = sod(&econtent, &other_attrs, &signature, &dsc);
        assert_eq!(
            witness(&swapped, &dg1, &pk, &sig, &request()).unwrap_err(),
            MrzError::MessageDigestMismatch
        );
    }

    #[test]
    fn refuses_a_device_signature_over_another_challenge() {
        let chip = fixtures::signed_chip();
        let (pk, sig) = device();
        let other = PassportMrzRequest {
            challenge: vec![9; 32],
            ..request()
        };
        assert_eq!(
            witness(&chip.sod, &chip.dg1, &pk, &sig, &other).unwrap_err(),
            MrzError::DeviceSignatureInvalid
        );
        assert_eq!(
            witness(&chip.sod, &chip.dg1, &pk[1..], &sig, &request()).unwrap_err(),
            MrzError::DeviceSignatureInvalid
        );
    }

    #[test]
    fn accepts_a_presentation_under_the_pinned_csca() {
        let chip = fixtures::signed_chip();
        let w = build(&chip).unwrap();
        let cscas = [chip.csca_cert.clone()];
        let out = check_presentation(
            &fake_proof(&w),
            &w.dsc_certificate,
            &trust_anchors(&cscas),
            &request(),
            NOW,
        )
        .unwrap();
        assert!(out.age_ok);
        assert_eq!(out.nationality, "TWN");
        assert_eq!(out.issuer_country, "TW");
    }

    #[test]
    fn refuses_a_dsc_no_pinned_csca_issued() {
        // The <= 0.4.0 hole: anyone can mint a DSC under any issuer name.
        let forged = fixtures::chip_with_dsc_signer(fixtures::fixture_dsc_key());
        let w = build(&forged).expect("the prover side cannot tell");
        let cscas = [forged.csca_cert.clone()];
        let proof = fake_proof(&w);
        assert_eq!(
            check_presentation(
                &proof,
                &w.dsc_certificate,
                &trust_anchors(&cscas),
                &request(),
                NOW
            )
            .unwrap_err(),
            MrzError::DscNotIssuedByPinnedCsca
        );
        assert_eq!(
            check_presentation(
                &proof,
                &w.dsc_certificate,
                &trust_anchors(&[]),
                &request(),
                NOW
            )
            .unwrap_err(),
            MrzError::DscNotIssuedByPinnedCsca
        );
    }

    #[test]
    fn refuses_expired_or_revoked_dscs() {
        let chip = fixtures::signed_chip();
        let w = build(&chip).unwrap();
        let cscas = [chip.csca_cert.clone()];
        let proof = fake_proof(&w);
        assert_eq!(
            check_presentation(
                &proof,
                &w.dsc_certificate,
                &trust_anchors(&cscas),
                &request(),
                AFTER_DSC_EXPIRY
            )
            .unwrap_err(),
            MrzError::CertificateNotValidNow
        );
        let revoked = [fixtures::FIXTURE_DSC_SERIAL.to_vec()];
        let trust = TrustAnchors {
            csca_certificates: &cscas,
            revoked_dsc_serials: &revoked,
        };
        assert_eq!(
            check_presentation(&proof, &w.dsc_certificate, &trust, &request(), NOW).unwrap_err(),
            MrzError::DscRevoked
        );
    }

    #[test]
    fn refuses_a_proof_for_another_dsc_or_another_request() {
        let chip = fixtures::signed_chip();
        let w = build(&chip).unwrap();
        let cscas = [chip.csca_cert.clone()];
        let trust = trust_anchors(&cscas);

        let mut other_dsc = w.clone();
        let csca_modulus = BigUint::from_bytes_be(&fixtures::fixture_csca_key().n().to_bytes_be());
        other_dsc.inputs.insert(
            "dsc_modulus_limbs".into(),
            limbs_120(&csca_modulus)
                .iter()
                .map(|f| decimal(*f))
                .collect(),
        );
        assert_eq!(
            check_presentation(
                &fake_proof(&other_dsc),
                &w.dsc_certificate,
                &trust,
                &request(),
                NOW
            )
            .unwrap_err(),
            MrzError::DscModulusMismatch
        );

        let proof = fake_proof(&w);
        for other in [
            PassportMrzRequest {
                challenge: vec![1; 32],
                ..request()
            },
            PassportMrzRequest {
                scope: "elsewhere".into(),
                ..request()
            },
            PassportMrzRequest {
                today: 20261031,
                ..request()
            },
            PassportMrzRequest {
                min_age: 21,
                ..request()
            },
            PassportMrzRequest {
                disclose_nationality: false,
                ..request()
            },
        ] {
            assert_eq!(
                check_presentation(&proof, &w.dsc_certificate, &trust, &other, NOW).unwrap_err(),
                MrzError::RequestMismatch
            );
        }

        let mut wrong_count = proof.clone();
        wrong_count[3] = 59;
        assert_eq!(
            check_presentation(&wrong_count, &w.dsc_certificate, &trust, &request(), NOW)
                .unwrap_err(),
            MrzError::MalformedProof
        );
    }

    // --- Real proofs (circuit JSON + SRS staged; run with --ignored --release) ---

    fn vectors_dir() -> std::path::PathBuf {
        std::env::var_os("PASSPORT_NOIR_VECTORS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")))
    }

    fn artifacts() -> Option<(String, String)> {
        let dir = vectors_dir().join("test-vectors");
        let circuit = dir.join("noir/passport_mrz.json");
        let srs = dir.join("srs/passport_mrz.srs.bin");
        (circuit.exists() && srs.exists()).then(|| {
            (
                circuit.to_string_lossy().into(),
                srs.to_string_lossy().into(),
            )
        })
    }

    #[test]
    #[ignore = "generates real proofs; cargo test --release passport_mrz -- --ignored"]
    fn real_proof_verifies_and_forgeries_do_not() {
        let Some((circuit, srs)) = artifacts() else {
            eprintln!("SKIP: test-vectors/noir/passport_mrz.json or srs/passport_mrz.srs.bin absent (make gen-srs-mrz)");
            return;
        };
        let chip = fixtures::signed_chip();
        let w = build(&chip).unwrap();
        let proof = crate::noir::generate_noir_proof_exact(&circuit, Some(&srs), w.inputs.clone())
            .expect("prove");
        let verify = |proof: Vec<u8>, cscas: Vec<Vec<u8>>, req: PassportMrzRequest| {
            verify_passport_mrz(
                circuit.clone(),
                Some(srs.clone()),
                proof,
                w.dsc_certificate.clone(),
                cscas,
                vec![],
                req,
                NOW,
            )
        };

        let out =
            verify(proof.proof.clone(), vec![chip.csca_cert.clone()], request()).expect("verifies");
        assert!(out.age_ok);
        assert_eq!(out.nationality, "TWN");
        assert_ne!(out.nullifier, "0".repeat(64));
        assert_ne!(out.device_tag, "0".repeat(64));

        // Same proof, verifier trusts nobody (or another CSCA): refused.
        assert!(verify(proof.proof.clone(), vec![], request()).is_err());

        // Flip the nullifier in the public inputs: the proof no longer verifies.
        let mut tampered = proof.proof.clone();
        tampered[4 + (PUBLIC_INPUT_COUNT - 1) * 32 + 31] ^= 1;
        let err = verify(tampered, vec![chip.csca_cert.clone()], request()).unwrap_err();
        assert!(err.to_string().contains("proof-invalid"), "{err}");

        // A DG1 the DSC never signed cannot be proven at all.
        let mut forged = w.inputs.clone();
        let mut dg1 = chip.dg1.clone();
        dg1[60] = b'X';
        forged.insert("dg1".into(), byte_strings(&dg1));
        assert!(crate::noir::generate_noir_proof_exact(&circuit, Some(&srs), forged).is_err());

        // No disclosure, no scope: age/nationality/nullifier are zero.
        let quiet = PassportMrzRequest {
            scope: String::new(),
            min_age: 0,
            disclose_nationality: false,
            ..request()
        };
        let (pk, sig) = device();
        let w2 = witness(&chip.sod, &chip.dg1, &pk, &sig, &quiet).unwrap();
        let p2 = crate::noir::generate_noir_proof_exact(&circuit, Some(&srs), w2.inputs)
            .expect("prove quiet");
        let out2 = verify(p2.proof, vec![chip.csca_cert.clone()], quiet).expect("quiet verifies");
        assert!(!out2.age_ok);
        assert_eq!(out2.nationality, "");
        assert_eq!(out2.nullifier, "0".repeat(64));
    }
}
