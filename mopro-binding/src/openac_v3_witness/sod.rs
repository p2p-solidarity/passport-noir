//! ICAO 9303 EF.SOD / DG1 / DG15 parsing and off-circuit integrity checks.
//!
//! The native NFC layer has already performed passive authentication against
//! the bundled CSCA Master List (the request's `passiveAuthValid` gate fails
//! closed before we get here). This module re-derives the pieces the OpenAC
//! v3 witnesses need from the raw chip files:
//!
//!   * LDS Security Object → digest algorithm + per-DG hashes, and the
//!     verification that the DG1/DG15 bytes the chip returned actually hash
//!     to the SOD-committed values (CMS messageDigest ↔ eContent included).
//!   * DSC certificate → 20-byte serial, SHA-256(TBS), issuer Name DER hash,
//!     AuthorityKeyIdentifier — the revocation + Master List matching keys.
//!   * DG15 → Active Authentication public key (EC P-256 only; the
//!     passport_adapter circuit verifies ECDSA-P256, so RSA-AA passports
//!     fail closed when AA is required).
//!
//! Parsing is BER-tolerant (asn1-rs `Any::from_ber`) because real-world SODs
//! are not always strict DER.

use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;
use x509_parser::der_parser::asn1_rs::{Any, Class, FromBer, Tag};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

#[derive(Debug, thiserror::Error)]
pub enum SodError {
    #[error("invalid-sod")]
    InvalidSod,
    #[error("unsupported-lds-digest")]
    UnsupportedLdsDigest,
    #[error("missing-dg-hash")]
    MissingDgHash,
    #[error("missing-dg15")]
    MissingDg15,
    #[error("sod-dg-hash-mismatch")]
    DgHashMismatch,
    #[error("invalid-dsc-cert")]
    InvalidDscCert,
    #[error("dsc-serial-too-long")]
    DscSerialTooLong,
    #[error("invalid-dg1")]
    InvalidDg1,
    #[error("invalid-dg15")]
    InvalidDg15,
    #[error("active-auth-unsupported-key")]
    UnsupportedAaKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlg {
    fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.3.14.3.2.26" => Some(Self::Sha1),
            "2.16.840.1.101.3.4.2.4" => Some(Self::Sha224),
            "2.16.840.1.101.3.4.2.1" => Some(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

pub struct ParsedDsc {
    /// Serial number left-padded to the 20-byte circuit width.
    pub serial20: [u8; 20],
    /// SHA-256 over the raw TBSCertificate bytes.
    pub tbs_sha256: [u8; 32],
    /// SHA-256 over the raw issuer Name DER (byte-exact CRL issuer matching).
    pub issuer_name_der_sha256: [u8; 32],
    /// AuthorityKeyIdentifier keyIdentifier, uppercase hex.
    pub authority_key_id_hex: Option<String>,
}

pub struct ParsedSod {
    /// LDS digest algorithm + DG-hash map — exposed for inspection/tests; the
    /// witness builder consumes the verification side effects, not the map.
    #[allow(dead_code)]
    pub lds_digest: DigestAlg,
    /// dgNumber → SOD-committed hash.
    #[allow(dead_code)]
    pub dg_hashes: BTreeMap<u8, Vec<u8>>,
    pub dsc: ParsedDsc,
}

pub enum AaPublicKey {
    P256 { x: [u8; 32], y: [u8; 32] },
}

// ---------------------------------------------------------------------------
// BER walking helpers
// ---------------------------------------------------------------------------

fn parse_any(input: &[u8]) -> Result<(Any<'_>, &[u8]), SodError> {
    let (rem, any) = Any::from_ber(input).map_err(|_| SodError::InvalidSod)?;
    Ok((any, rem))
}

/// Children of a constructed element, with the raw element bytes of each.
fn children<'a>(any: &'a Any<'a>) -> Result<Vec<(Any<'a>, &'a [u8])>, SodError> {
    let mut out = Vec::new();
    let mut rest = any.data;
    while !rest.is_empty() {
        let before = rest;
        let (child, rem) = parse_any(rest)?;
        let consumed = before.len() - rem.len();
        out.push((child, &before[..consumed]));
        rest = rem;
    }
    Ok(out)
}

fn expect_oid_string(any: &Any<'_>) -> Result<String, SodError> {
    let oid = any.clone().oid().map_err(|_| SodError::InvalidSod)?;
    Ok(oid.to_id_string())
}

fn int_as_u64(any: &Any<'_>) -> Result<u64, SodError> {
    let int = any.clone().integer().map_err(|_| SodError::InvalidSod)?;
    int.as_u64().map_err(|_| SodError::InvalidSod)
}

// ---------------------------------------------------------------------------
// EF.SOD (CMS SignedData wrapping the LDS Security Object)
// ---------------------------------------------------------------------------

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_MESSAGE_DIGEST_ATTR: &str = "1.2.840.113549.1.9.4";

/// Parse the SOD, verify the chip's DG1/DG15 bytes against the LDS-committed
/// hashes (and the CMS messageDigest against the eContent), and extract the
/// DSC certificate fields.
#[allow(dead_code)]
pub fn parse_sod(sod_bytes: &[u8], dg1: &[u8], dg15: &[u8]) -> Result<ParsedSod, SodError> {
    parse_sod_optional_dg15(sod_bytes, dg1, Some(dg15))
}

/// Same as `parse_sod`, but allows a passive-only passport whose SOD does not
/// advertise DG15. If SOD advertises DG15 but the caller did not provide it,
/// fail closed instead of silently downgrading an AA-capable passport.
pub fn parse_sod_optional_dg15(
    sod_bytes: &[u8],
    dg1: &[u8],
    dg15: Option<&[u8]>,
) -> Result<ParsedSod, SodError> {
    // EF.SOD is the ContentInfo wrapped in an ICAO application tag 0x77.
    // Tolerate both the wrapped file and a bare ContentInfo.
    let (outer, _) = parse_any(sod_bytes)?;
    let content_info = if outer.header.class() == Class::Application {
        let (inner, _) = parse_any(outer.data)?;
        inner
    } else {
        outer
    };

    // ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
    let ci_children = children(&content_info)?;
    if ci_children.len() < 2 {
        return Err(SodError::InvalidSod);
    }
    if expect_oid_string(&ci_children[0].0)? != OID_SIGNED_DATA {
        return Err(SodError::InvalidSod);
    }
    let (signed_data_any, _) = parse_any(ci_children[1].0.data)?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //                           certificates [0] IMPLICIT OPTIONAL, crls [1],
    //                           signerInfos }
    let sd = children(&signed_data_any)?;
    if sd.len() < 4 {
        return Err(SodError::InvalidSod);
    }
    let mut idx = 0;
    // version
    let _ = int_as_u64(&sd[idx].0)?;
    idx += 1;
    // digestAlgorithms (SET) — skip; per-signer algorithm is authoritative.
    idx += 1;
    // encapContentInfo ::= SEQUENCE { eContentType OID, [0] EXPLICIT OCTET STRING }
    let econtent = {
        let eci = children(&sd[idx].0)?;
        if eci.len() < 2 {
            return Err(SodError::InvalidSod);
        }
        let (octet, _) = parse_any(eci[1].0.data)?;
        // Constructed OCTET STRING (BER) concatenates primitive chunks.
        if octet.header.constructed() {
            let mut joined = Vec::new();
            for (chunk, _) in children(&octet)? {
                joined.extend_from_slice(chunk.data);
            }
            joined
        } else {
            octet.data.to_vec()
        }
    };
    idx += 1;

    // certificates [0] IMPLICIT — required for ICAO SODs (carries the DSC).
    let mut dsc_der: Option<&[u8]> = None;
    if idx < sd.len()
        && sd[idx].0.header.class() == Class::ContextSpecific
        && sd[idx].0.header.tag() == Tag(0)
    {
        let certs = children(&sd[idx].0)?;
        if let Some((_, raw)) = certs.first() {
            dsc_der = Some(raw);
        }
        idx += 1;
    }
    // crls [1] IMPLICIT — skip when present.
    if idx < sd.len()
        && sd[idx].0.header.class() == Class::ContextSpecific
        && sd[idx].0.header.tag() == Tag(1)
    {
        idx += 1;
    }
    let dsc_der = dsc_der.ok_or(SodError::InvalidDscCert)?;

    // signerInfos ::= SET OF SignerInfo. Exactly one signer for ICAO.
    let signer_infos = sd.get(idx).ok_or(SodError::InvalidSod)?;
    let signer = children(&signer_infos.0)?;
    let signer = signer.first().ok_or(SodError::InvalidSod)?;
    let si = children(&signer.0)?;
    if si.len() < 4 {
        return Err(SodError::InvalidSod);
    }
    // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm AlgorithmIdentifier,
    //                           signedAttrs [0] IMPLICIT OPTIONAL, ... }
    let signer_digest = {
        let alg = children(&si[2].0)?;
        let oid = expect_oid_string(&alg.first().ok_or(SodError::InvalidSod)?.0)?;
        DigestAlg::from_oid(&oid).ok_or(SodError::UnsupportedLdsDigest)?
    };

    // messageDigest signed attribute must equal digest(eContent) — the same
    // integrity link passive auth verified natively; re-checked here so a
    // mismatched eContent can never produce witnesses.
    if let Some(attrs) = si.get(3) {
        if attrs.0.header.class() == Class::ContextSpecific && attrs.0.header.tag() == Tag(0) {
            let mut message_digest: Option<Vec<u8>> = None;
            for (attr, _) in children(&attrs.0)? {
                let parts = children(&attr)?;
                if parts.len() >= 2 && expect_oid_string(&parts[0].0)? == OID_MESSAGE_DIGEST_ATTR {
                    let values = children(&parts[1].0)?;
                    if let Some((value, _)) = values.first() {
                        message_digest = Some(value.data.to_vec());
                    }
                }
            }
            if let Some(expected) = message_digest {
                if signer_digest.digest(&econtent) != expected {
                    return Err(SodError::DgHashMismatch);
                }
            }
        }
    }

    // LDSSecurityObject ::= SEQUENCE { version, hashAlgorithm, SEQUENCE OF
    //                                  { dgNumber INTEGER, hash OCTET STRING } }
    let (lds_any, _) = parse_any(&econtent)?;
    let lds = children(&lds_any)?;
    if lds.len() < 3 {
        return Err(SodError::InvalidSod);
    }
    let lds_digest = {
        let alg = children(&lds[1].0)?;
        let oid = expect_oid_string(&alg.first().ok_or(SodError::InvalidSod)?.0)?;
        DigestAlg::from_oid(&oid).ok_or(SodError::UnsupportedLdsDigest)?
    };
    let mut dg_hashes = BTreeMap::new();
    for (entry, _) in children(&lds[2].0)? {
        let parts = children(&entry)?;
        if parts.len() < 2 {
            return Err(SodError::InvalidSod);
        }
        let dg_number = int_as_u64(&parts[0].0)? as u8;
        let hash = parts[1].0.data.to_vec();
        dg_hashes.insert(dg_number, hash);
    }

    // Chip bytes must hash to the SOD-committed values.
    let dg1_expected = dg_hashes.get(&1).ok_or(SodError::MissingDgHash)?;
    if &lds_digest.digest(dg1) != dg1_expected {
        return Err(SodError::DgHashMismatch);
    }
    if let Some(dg15) = dg15 {
        let dg15_expected = dg_hashes.get(&15).ok_or(SodError::MissingDgHash)?;
        if &lds_digest.digest(dg15) != dg15_expected {
            return Err(SodError::DgHashMismatch);
        }
    } else if dg_hashes.contains_key(&15) {
        return Err(SodError::MissingDg15);
    }

    let dsc = parse_dsc(dsc_der)?;

    Ok(ParsedSod {
        lds_digest,
        dg_hashes,
        dsc,
    })
}

fn parse_dsc(der: &[u8]) -> Result<ParsedDsc, SodError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| SodError::InvalidDscCert)?;

    let serial_bytes = cert.tbs_certificate.serial.to_bytes_be();
    // Strip any leading zero sign byte, then left-pad to 20.
    let trimmed: Vec<u8> = serial_bytes
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    if trimmed.len() > 20 {
        return Err(SodError::DscSerialTooLong);
    }
    let mut serial20 = [0u8; 20];
    serial20[20 - trimmed.len()..].copy_from_slice(&trimmed);

    let tbs_sha256: [u8; 32] = Sha256::digest(cert.tbs_certificate.as_ref()).into();
    let issuer_name_der_sha256: [u8; 32] =
        Sha256::digest(cert.tbs_certificate.issuer.as_raw()).into();

    let mut authority_key_id_hex = None;
    for ext in cert.tbs_certificate.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            if let Some(key_id) = &aki.key_identifier {
                authority_key_id_hex = Some(hex_upper(key_id.0));
            }
        }
    }

    Ok(ParsedDsc {
        serial20,
        tbs_sha256,
        issuer_name_der_sha256,
        authority_key_id_hex,
    })
}

pub fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

// ---------------------------------------------------------------------------
// DG1 (MRZ) and DG15 (Active Authentication public key)
// ---------------------------------------------------------------------------

/// Extract the 88-byte TD3 MRZ from the DG1 TLV (`61 L { 5F1F L mrz }`).
pub fn parse_dg1_mrz(dg1: &[u8]) -> Result<[u8; 88], SodError> {
    let (outer, _) = parse_any(dg1).map_err(|_| SodError::InvalidDg1)?;
    if outer.header.class() != Class::Application {
        return Err(SodError::InvalidDg1);
    }
    let (mrz_any, _) = parse_any(outer.data).map_err(|_| SodError::InvalidDg1)?;
    let mrz = mrz_any.data;
    if mrz.len() != 88 {
        return Err(SodError::InvalidDg1);
    }
    let mut out = [0u8; 88];
    out.copy_from_slice(mrz);
    Ok(out)
}

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";

/// Extract the AA public key from DG15 (`6F L { SubjectPublicKeyInfo }`).
/// Only EC P-256 keys are supported — the passport_adapter circuit verifies
/// ECDSA-P256 over the AA challenge, and the normalised DG15 layout the DG
/// chain hashes is the raw `x || y` point.
pub fn parse_dg15_aa_key(dg15: &[u8]) -> Result<AaPublicKey, SodError> {
    let (outer, _) = parse_any(dg15).map_err(|_| SodError::InvalidDg15)?;
    let spki_bytes = if outer.header.class() == Class::Application {
        outer.data
    } else {
        dg15
    };

    let (spki, _) = parse_any(spki_bytes).map_err(|_| SodError::InvalidDg15)?;
    let parts = children(&spki).map_err(|_| SodError::InvalidDg15)?;
    if parts.len() < 2 {
        return Err(SodError::InvalidDg15);
    }
    let alg = children(&parts[0].0).map_err(|_| SodError::InvalidDg15)?;
    let alg_oid = expect_oid_string(&alg.first().ok_or(SodError::InvalidDg15)?.0)
        .map_err(|_| SodError::InvalidDg15)?;
    if alg_oid != OID_EC_PUBLIC_KEY {
        return Err(SodError::UnsupportedAaKey);
    }
    if let Some((params, _)) = alg.get(1) {
        match expect_oid_string(params) {
            Ok(curve) if curve == OID_P256 => {}
            Ok(_) => return Err(SodError::UnsupportedAaKey),
            // Non-OID params (explicit EC params) — unsupported profile.
            Err(_) => return Err(SodError::UnsupportedAaKey),
        }
    }

    let bit_string = parts[1]
        .0
        .clone()
        .bitstring()
        .map_err(|_| SodError::InvalidDg15)?;
    let point = bit_string.data;
    if point.len() == 65 && point[0] == 0x04 {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&point[1..33]);
        y.copy_from_slice(&point[33..65]);
        return Ok(AaPublicKey::P256 { x, y });
    }
    if point.len() == 33 && (point[0] == 0x02 || point[0] == 0x03) {
        // Compressed point — decompress via the p256 crate.
        use p256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
        let encoded =
            EncodedPoint::<p256::NistP256>::from_bytes(point).map_err(|_| SodError::InvalidDg15)?;
        let key = p256::PublicKey::from_encoded_point(&encoded);
        let key = Option::<p256::PublicKey>::from(key).ok_or(SodError::InvalidDg15)?;
        let uncompressed = key.to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(uncompressed.x().ok_or(SodError::InvalidDg15)?);
        y.copy_from_slice(uncompressed.y().ok_or(SodError::InvalidDg15)?);
        return Ok(AaPublicKey::P256 { x, y });
    }
    Err(SodError::UnsupportedAaKey)
}

/// MRZ-derived claims for `pack_passport_claims` (TD3 line 2: nationality at
/// [54..57), birth date YYMMDD at [57..63)).
pub struct MrzClaims {
    pub birth_year: u32,
    pub birth_month: u32,
    pub birth_day: u32,
    pub nationality: [u8; 3],
}

pub fn mrz_claims(mrz: &[u8; 88]) -> Result<MrzClaims, SodError> {
    let digit = |i: usize| -> Result<u32, SodError> {
        let b = mrz[i];
        if !b.is_ascii_digit() {
            return Err(SodError::InvalidDg1);
        }
        Ok((b - b'0') as u32)
    };
    let yy = digit(57)? * 10 + digit(58)?;
    let birth_month = digit(59)? * 10 + digit(60)?;
    let birth_day = digit(61)? * 10 + digit(62)?;
    // openac_core::predicate::two_digit_year_to_four with pivot 50.
    let birth_year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    let nationality = [mrz[54], mrz[55], mrz[56]];
    Ok(MrzClaims {
        birth_year,
        birth_month,
        birth_day,
        nationality,
    })
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    //! Synthetic-but-structurally-real chip fixture: a DER SOD signed by a
    //! fixture DSC, DG1 with a valid TD3 MRZ, DG15 with a P-256 AA key.
    //! Built by `super::super::fixtures`.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openac_v3_witness::fixtures;

    #[test]
    fn parses_fixture_sod_and_verifies_dg_hashes() {
        let chip = fixtures::fixture_chip();
        let parsed = parse_sod(&chip.sod, &chip.dg1, &chip.dg15).expect("fixture SOD parses");
        assert_eq!(parsed.lds_digest, DigestAlg::Sha256);
        assert_eq!(
            parsed.dsc.serial20[19],
            fixtures::FIXTURE_DSC_SERIAL_LAST_BYTE
        );
        assert!(parsed.dg_hashes.contains_key(&1));
        assert!(parsed.dg_hashes.contains_key(&15));
    }

    #[test]
    fn rejects_tampered_dg1() {
        let chip = fixtures::fixture_chip();
        let mut dg1 = chip.dg1.clone();
        let last = dg1.len() - 1;
        dg1[last] ^= 0xFF;
        assert!(matches!(
            parse_sod(&chip.sod, &dg1, &chip.dg15),
            Err(SodError::DgHashMismatch)
        ));
    }

    #[test]
    fn extracts_mrz_and_claims() {
        let chip = fixtures::fixture_chip();
        let mrz = parse_dg1_mrz(&chip.dg1).expect("MRZ extracts");
        let claims = mrz_claims(&mrz).expect("claims parse");
        assert_eq!(claims.nationality, *b"TWN");
        assert_eq!(claims.birth_year, 1990);
        assert_eq!(claims.birth_month, 1);
        assert_eq!(claims.birth_day, 1);
    }

    #[test]
    fn extracts_p256_aa_key() {
        let chip = fixtures::fixture_chip();
        let AaPublicKey::P256 { x, y } = parse_dg15_aa_key(&chip.dg15).expect("AA key");
        assert_ne!(x, [0u8; 32]);
        assert_ne!(y, [0u8; 32]);
    }
}
