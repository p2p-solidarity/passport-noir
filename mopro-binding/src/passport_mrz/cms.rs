//! ICAO 9303 EF.SOD (CMS SignedData) → the exact bytes the issuing state's
//! DSC signed. BER-tolerant on the outer layers (real SODs are not always
//! strict DER); the SignedAttributes are DER by CMS rule (RFC 5652 §5.4), so
//! re-tagging `[0] IMPLICIT` → `SET` reproduces the signed bytes.

use x509_parser::der_parser::asn1_rs::{Any, Class, FromBer, Tag};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid-sod")]
pub struct InvalidSod;

pub struct SignedParts {
    /// LDSSecurityObject (the encapsulated content).
    pub econtent: Vec<u8>,
    /// SignerInfo.signedAttrs, DER `SET` encoded (tag 0x31) — what the DSC signed.
    pub signed_attrs: Vec<u8>,
    /// SignerInfo.digestAlgorithm OID.
    pub digest_oid: String,
    /// SignerInfo.signatureAlgorithm OID.
    pub signature_oid: String,
    pub signature: Vec<u8>,
    /// The DSC certificate carried in SignedData.certificates.
    pub dsc_der: Vec<u8>,
}

fn parse_any(input: &[u8]) -> Result<(Any<'_>, &[u8]), InvalidSod> {
    let (rem, any) = Any::from_ber(input).map_err(|_| InvalidSod)?;
    Ok((any, rem))
}

/// Children of a constructed element, with the raw element bytes of each.
fn children<'a>(any: &'a Any<'a>) -> Result<Vec<(Any<'a>, &'a [u8])>, InvalidSod> {
    let mut out = Vec::new();
    let mut rest = any.data;
    while !rest.is_empty() {
        let before = rest;
        let (child, rem) = parse_any(rest)?;
        out.push((child, &before[..before.len() - rem.len()]));
        rest = rem;
    }
    Ok(out)
}

fn oid_string(any: &Any<'_>) -> Result<String, InvalidSod> {
    Ok(any.clone().oid().map_err(|_| InvalidSod)?.to_id_string())
}

fn first_oid(any: &Any<'_>) -> Result<String, InvalidSod> {
    oid_string(&children(any)?.first().ok_or(InvalidSod)?.0)
}

fn is_context(any: &Any<'_>, tag: u32) -> bool {
    any.header.class() == Class::ContextSpecific && any.header.tag() == Tag(tag)
}

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

pub fn signed_parts(sod: &[u8]) -> Result<SignedParts, InvalidSod> {
    // EF.SOD is the ContentInfo wrapped in ICAO application tag 0x77.
    let (outer, _) = parse_any(sod)?;
    let content_info = if outer.header.class() == Class::Application {
        parse_any(outer.data)?.0
    } else {
        outer
    };
    let ci = children(&content_info)?;
    if ci.len() < 2 || oid_string(&ci[0].0)? != OID_SIGNED_DATA {
        return Err(InvalidSod);
    }
    let (signed_data, _) = parse_any(ci[1].0.data)?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos }
    let sd = children(&signed_data)?;
    if sd.len() < 4 {
        return Err(InvalidSod);
    }
    let econtent = {
        let eci = children(&sd[2].0)?;
        let (octet, _) = parse_any(eci.get(1).ok_or(InvalidSod)?.0.data)?;
        if octet.header.constructed() {
            // Constructed OCTET STRING (BER) concatenates primitive chunks.
            children(&octet)?
                .iter()
                .flat_map(|(c, _)| c.data.to_vec())
                .collect()
        } else {
            octet.data.to_vec()
        }
    };
    let mut idx = 3;
    let mut dsc_der = None;
    if is_context(&sd[idx].0, 0) {
        dsc_der = children(&sd[idx].0)?.first().map(|(_, raw)| raw.to_vec());
        idx += 1;
    }
    if idx < sd.len() && is_context(&sd[idx].0, 1) {
        idx += 1;
    }
    let dsc_der = dsc_der.ok_or(InvalidSod)?;

    // signerInfos: exactly one signer for ICAO.
    let signers = children(&sd.get(idx).ok_or(InvalidSod)?.0)?;
    if signers.len() != 1 {
        return Err(InvalidSod);
    }
    // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
    //   signedAttrs [0] IMPLICIT, signatureAlgorithm, signature, ... }
    let si = children(&signers[0].0)?;
    if si.len() < 6 || !is_context(&si[3].0, 0) || !si[3].0.header.constructed() {
        return Err(InvalidSod);
    }
    let mut signed_attrs = si[3].1.to_vec();
    signed_attrs[0] = 0x31;
    Ok(SignedParts {
        econtent,
        signed_attrs,
        digest_oid: first_oid(&si[2].0)?,
        signature_oid: first_oid(&si[4].0)?,
        signature: si[5].0.data.to_vec(),
        dsc_der,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passport_mrz::fixtures;

    #[test]
    fn extracts_the_signed_bytes_of_a_fixture_sod() {
        let chip = fixtures::signed_chip();
        let parts = signed_parts(&chip.sod).expect("fixture SOD parses");
        assert_eq!(parts.signed_attrs[0], 0x31);
        assert_eq!(parts.digest_oid, "2.16.840.1.101.3.4.2.1");
        assert_eq!(parts.signature_oid, "1.2.840.113549.1.1.11");
        assert_eq!(parts.signature.len(), 256);
        assert_eq!(parts.dsc_der, chip.dsc_cert);
    }

    #[test]
    fn rejects_bytes_that_are_not_a_sod() {
        assert!(signed_parts(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
        assert!(signed_parts(&[]).is_err());
    }
}
