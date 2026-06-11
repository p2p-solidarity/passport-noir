//! Test-only synthetic chip fixture: a structurally real EF.SOD (CMS
//! SignedData with an embedded DSC certificate and LDS Security Object),
//! DG1 with a valid TD3 MRZ, and DG15 carrying a P-256 AA public key whose
//! private half the tests control (so Active Authentication evidence can be
//! produced). The CMS signature value is a placeholder — the witness builder
//! never re-verifies it (native passive auth owns chain verification); it
//! does verify DG hashes and the messageDigest ↔ eContent link, which this
//! fixture satisfies for real.

#![cfg(test)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const FIXTURE_DSC_SERIAL_LAST_BYTE: u8 = 0x89;
pub const FIXTURE_DSC_SERIAL: [u8; 5] = [0x01, 0x23, 0x45, 0x67, 0x89];
pub const FIXTURE_AKI: [u8; 20] = [0xA1; 20];

// ---------------------------------------------------------------------------
// Minimal DER writer
// ---------------------------------------------------------------------------

pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut rest = len;
        while rest > 0 {
            len_bytes.push((rest & 0xFF) as u8);
            rest >>= 8;
        }
        len_bytes.reverse();
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(content);
    out
}

fn der_concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

pub fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &der_concat(parts))
}

pub fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x31, &der_concat(parts))
}

pub fn der_oid(oid: &str) -> Vec<u8> {
    let arcs: Vec<u64> = oid.split('.').map(|p| p.parse().unwrap()).collect();
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut chunk = Vec::new();
        let mut rest = *arc;
        loop {
            chunk.push((rest & 0x7F) as u8);
            rest >>= 7;
            if rest == 0 {
                break;
            }
        }
        chunk.reverse();
        let last = chunk.len() - 1;
        for (i, b) in chunk.iter().enumerate() {
            content.push(if i == last { *b } else { *b | 0x80 });
        }
    }
    der(0x06, &content)
}

pub fn der_int_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut content: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der(0x02, &content)
}

pub fn der_int(value: u64) -> Vec<u8> {
    der_int_bytes(&value.to_be_bytes())
}

pub fn der_octet(content: &[u8]) -> Vec<u8> {
    der(0x04, content)
}

pub fn der_null() -> Vec<u8> {
    der(0x05, &[])
}

pub fn der_bitstring(content: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8];
    padded.extend_from_slice(content);
    der(0x03, &padded)
}

fn der_utf8(text: &str) -> Vec<u8> {
    der(0x0C, text.as_bytes())
}

fn der_utctime(text: &str) -> Vec<u8> {
    der(0x17, text.as_bytes())
}

// ---------------------------------------------------------------------------
// Fixture keys
// ---------------------------------------------------------------------------

const FIXTURE_CSCA_RSA_B64: &str = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCrNDNLoWK4pJl7/jYwxlQR6LQVWwmlGGNmxaHRgxvkucPYX2vpvhgBv8v62i5BzeWCAJFY2l+KzuQ1SaaOeHHgy7xVQwjs46eiet7NOSbchOMPR8S9lhqddJPDFLG/LxuA7X6CKO7wbAxOnGdT65iPLhV06cWJa409CMbGqKA9qj423LvLyZ2Aj366d7i8ST3PHP5GgAyrKsLBVuCRMM/vqlYGXCep9Lq31CgEYQJN+oWA+7GBJNYeyE3C7VTLCsP4fxJSCvLms2liA94ALDpgXsgysCscdDmNo3BUvzZ0TJqoe1/CN5Hv6zgUVFOL0Ko4bcHIaABY2NMXA4ThpWvlAgMBAAECggEAENXKv4Korwh8kU1Prd8q0DIGV11C5wmtaKNBhNU0Lns373R+q5cGTFG8cLf4uX7SNUTyBf8/SuqKVVUfPD5K0HSoWegEHitKxjb35s1abW/h1hRUG+KBTn9yskm8KtUqirSP7qOwz1KIqUhG/uEZeObqtDrysk8xrdFJnqphS37jbyWIu/3MJRO2En8GXTq71PpKevPfzRkkezd2GXnc6HEd29e1pGFu47H4jwUAg2/TW57KzOzce/xPk89U4v+uI/JASVLlZHUDr6vPXktqY8/sri4y7qC9fibyVgkM58gUdwVSDPCxmXV3ciZajcHKfwtuUPEx532uAcPkrU51BwKBgQDdfv4DDLXe2NQwKfoZ9zl71oQ4YbqBCz2ShjCtE5f/RkFpSa+Q9JDzyul4obwJdCuaunfzL8Y96MyrY8hjUvHyzu9iDEq3vEtw0jxy6dkDGWDXc1dJECyNRgSG84459crarnS7Y+b/pdY73gPuWcB2p4/v6wRgmav/85zMF9X1wwKBgQDF351rpDj6+xPx0iuObuWRjyo5LqnoTSoKxvCFj/2UP+cJLk0nJAR9Iib0tCe90tztidSfzSR2X03H0476ZNQHnl+X+neRVRfSjvb8aZ1VTKjzn42XjYjLmzO3qoGRgTp+2HKwHcYSppiYC0LrvFP/+KC//n+dkw748ArXzf71NwKBgQDY/axDuJQD+VAGz1jhTz3VgFaQFc3s1eJARY4yQNvLjjxOtY116OKIs+T99RSN/m0pbDxO1iLUS9kWnu6Vv5CgWvJRj9EzJxiRMqVdvpKHYrlo2OpN/bZnwIx22OwhBBbzHa3mVvzavtCeXeZj/zF6DLYKSKdFK8dBPJwDpeZKmQKBgQC+ZEphL1PQUtQ/Ax3738KuixVyje7YYZ8JXaBCs2ioQ9B26gE8nxBeowTewZXXtVP0j4Fx/X6PE2aQ1oQlc+z8I6wRXOO9iCXy6LLH7ot/btLGD4i7AWlVl9FscPhY3AI/2N6JjSxv97Kt4XATyVL94eoysptyL/ThHH8iZMhkgwKBgQCPRF5vJkC34g/l/+iA13QKRUl/DFER9/EKiGexKTkMMCYDwSiqMzIpDgWSQCH9b/GchctyXJkSB9nvtoLgFscAMtnKqrsuKaEPD1tTmDT4inpe1sbgvuSs+IXE2RBkEspuicTOk6ouaGANdia96Kqj/08LRUjZHXBFsAMUIKqR7A==";

const FIXTURE_DSC_RSA_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDeblVi8GgLRKUNiLyh8NjEKJk0dzq/9xKJ/qZcLcjTxL3xbgX8rWP42YmmmrG8FRmPmr/R6kJOFp6RvktWlA8Oyo3rPbwmoNgyRgoMiOBprFb1jbh8wQuiVuHFbXGRr1K3fiKcu5w4Jo3cTdNEABidwk3haBwUpEgwsiTa61/JIinrh6TlaxBmgVtYW5Hxar7sUYuToxseBgFAMCw3WhQb454bkFuyrC86u38bqymjvCRqkqaRML7BJBkCIyaxWzkvWDs6lCz0CChMHTLZ7mJKiX2YeDpo+wrti5jR/EtdLA+9IThdsv1O5UU1CFTP0UcdZ6SU7Q+juR1GeCoemtMRAgMBAAECggEAHrgILNjc1amOTfczbf4QQc8FkZxhzb82nT5BBXwBP1XtkZlLVGEx7F1GyG6W203isNWDZl8+9v/iuGgaiYN7LOTGgtWM1ZzjHtZTbvW8YHu/qrv+3aPfknUDSzvZMnCPMO5Ho3O5mHuinelVow+MVsVN8jJppmQl4CvKMT3Ohb1jJmB9pxgx0U4ZcOjSKDZ5BjSryxs+42DksruxbR6WCVGrqKXfzd5to/H4316hXqjWHndpTzRJlU2P2YkBfvSUsNuCbKZIfcVpfP4LjnnxmIbvLteHVKOCTRvQ9sPwrVUK91I/1zu/09CClUL5l81f60uaXa2R8jJgtnLY6zI2DQKBgQD6LtivkRleqMnS1EypDj3X/jk9CkGj9nqn2J1eZ5bOaIHMiC1L2vuNvoJo3FwDg0UvlNZpuZ9TFu/M/oTHo4b7WUbI59L8L78J/QKihksST+2aqAlsTLoXsIki1agvPIyPjIeoOBISJk2F9EK3UDlpFQ2qPlM3KoghUp39FkJDFwKBgQDjmkzPuSDSXeu5iDVnD+c0A3VG4L/ZkNL9qUt3flxQQN4oD0jqHmTQmJpcftl3RBGQXGjVgKmGUfQdp1TcILFDmAHMJjchqVVi6joyv3ioaQPsgWz2NmvNZ6ioFrhr2lEIMrcPEprdMtJ0Kj3wsD4vpEus+R+j7ZJQBJviP38UFwKBgDReFfE5+At+XTCKS7mfR4asqiKCwRanAymbB+W43TI7YeAEKScVoU4cMIPujDwYACVjjDX5KsZjqLJKHFUFf72hBFYNYHZ1MBHRKfoHDjO5E00qGz7WGKXYx/vIqTmp/OoXSlYF1pKB/fwqEsT4P+wlAgU+ooCLoI8JEhTl0dzlAoGAdOsUvjh5lddNeldwJ2tR97Q3EJvvsdHlsQzAibfNsCRCew2vBSVr4IQj95PqHoxHAYOXDuYzL5716i3FN/dLWE/DzJ1tAMu94zwzfVJCpzCbJWkvEiPOqQuw5fgV8MGLksyKoSGLkEnFNotkmjnPGCYsAcVP7aPi31wev9CidS0CgYAFM/VkdKc2UItJLmnkXd3mFfoCaVOhP2H0JNjk32zIzs9sxSLlvATWLHU2UiJApMwOVGJxlrYetu2Ew20qb+KLjXbMERuO9SFSuMOJy1OTBDZ7SppGihRIhVdrIuabqMe/gjn2gHcynaO0IcoL8ZUQCJUxqCSJPwJPV7RrnOXxsQ==";

/// Deterministic fixture RSA keys (2048-bit, generated once offline) so debug
/// test runs skip the multi-second keygen.
pub fn fixture_csca_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let der = STANDARD
            .decode(FIXTURE_CSCA_RSA_B64)
            .expect("fixture base64");
        RsaPrivateKey::from_pkcs8_der(&der).expect("fixture CSCA key")
    })
}

pub fn fixture_dsc_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let der = STANDARD
            .decode(FIXTURE_DSC_RSA_B64)
            .expect("fixture base64");
        RsaPrivateKey::from_pkcs8_der(&der).expect("fixture DSC key")
    })
}

/// Deterministic P-256 AA key (the fixture chip's Active Authentication key).
pub fn fixture_aa_key() -> SigningKey {
    let mut secret = [0x42u8; 32];
    secret[31] = 0x01;
    SigningKey::from_slice(&secret).expect("fixture AA scalar")
}

// ---------------------------------------------------------------------------
// MRZ (TD3)
// ---------------------------------------------------------------------------

fn check_digit(field: &str) -> u8 {
    const WEIGHTS: [u32; 3] = [7, 3, 1];
    let mut sum = 0u32;
    for (i, ch) in field.chars().enumerate() {
        let v = match ch {
            '0'..='9' => ch as u32 - '0' as u32,
            'A'..='Z' => ch as u32 - 'A' as u32 + 10,
            _ => 0,
        };
        sum += v * WEIGHTS[i % 3];
    }
    (sum % 10) as u8
}

pub fn fixture_mrz() -> [u8; 88] {
    let line1 = format!("P<TWN{:<39}", "LIN<<MEI<HUA").replace(' ', "<");
    let doc = "L898902C3";
    let dob = "900101";
    let exp = "301231";
    let personal = "<".repeat(14);
    let composite_src = format!(
        "{doc}{}{dob}{}{exp}{}{personal}{}",
        check_digit(doc),
        check_digit(dob),
        check_digit(exp),
        check_digit(&personal)
    );
    let line2 = format!(
        "{doc}{}TWN{dob}{}F{exp}{}{personal}{}{}",
        check_digit(doc),
        check_digit(dob),
        check_digit(exp),
        check_digit(&personal),
        check_digit(&composite_src)
    );
    assert_eq!(line1.len(), 44);
    assert_eq!(line2.len(), 44);
    let mut out = [0u8; 88];
    out[..44].copy_from_slice(line1.as_bytes());
    out[44..].copy_from_slice(line2.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Chip files
// ---------------------------------------------------------------------------

pub struct FixtureChip {
    pub sod: Vec<u8>,
    pub dg1: Vec<u8>,
    pub dg15: Vec<u8>,
    pub dsc_tbs_sha256: [u8; 32],
    pub csca_name_der_sha256: [u8; 32],
}

fn fixture_name(common_name: &str) -> Vec<u8> {
    der_seq(&[
        der_set(&[der_seq(&[der_oid("2.5.4.6"), der(0x13, b"TW")])]),
        der_set(&[der_seq(&[der_oid("2.5.4.3"), der_utf8(common_name)])]),
    ])
}

fn rsa_spki(key: &RsaPrivateKey) -> Vec<u8> {
    use rsa::traits::PublicKeyParts;
    let pub_seq = der_seq(&[
        der_int_bytes(&key.n().to_bytes_be()),
        der_int_bytes(&key.e().to_bytes_be()),
    ]);
    der_seq(&[
        der_seq(&[der_oid("1.2.840.113549.1.1.1"), der_null()]),
        der_bitstring(&pub_seq),
    ])
}

fn fixture_dsc_cert() -> (Vec<u8>, [u8; 32], Vec<u8>) {
    let issuer = fixture_name("Fixture CSCA");
    let subject = fixture_name("Fixture DSC");
    let validity = der_seq(&[der_utctime("260101000000Z"), der_utctime("360101000000Z")]);

    // AuthorityKeyIdentifier extension: SEQ { [0] IMPLICIT keyIdentifier }.
    let aki_value = der_seq(&[der(0x80, &FIXTURE_AKI)]);
    let aki_ext = der_seq(&[der_oid("2.5.29.35"), der_octet(&aki_value)]);
    let extensions = der(0xA3, &der_seq(&[aki_ext]));

    let tbs = der_seq(&[
        der(0xA0, &der_int(2)), // version v3
        der_int_bytes(&FIXTURE_DSC_SERIAL),
        der_seq(&[der_oid("1.2.840.113549.1.1.11"), der_null()]),
        issuer.clone(),
        validity,
        subject,
        rsa_spki(fixture_dsc_key()),
        extensions,
    ]);
    let tbs_sha256: [u8; 32] = Sha256::digest(&tbs).into();

    let cert = der_seq(&[
        tbs,
        der_seq(&[der_oid("1.2.840.113549.1.1.11"), der_null()]),
        der_bitstring(&[0u8; 256]),
    ]);
    (cert, tbs_sha256, issuer)
}

pub fn fixture_dg15(aa_key: &SigningKey) -> Vec<u8> {
    let point = aa_key.verifying_key().to_encoded_point(false);
    let spki = der_seq(&[
        der_seq(&[der_oid("1.2.840.10045.2.1"), der_oid("1.2.840.10045.3.1.7")]),
        der_bitstring(point.as_bytes()),
    ]);
    der(0x6F, &spki)
}

pub fn fixture_chip() -> FixtureChip {
    fixture_chip_with_dg15(true)
}

pub fn fixture_chip_without_dg15() -> FixtureChip {
    fixture_chip_with_dg15(false)
}

fn fixture_chip_with_dg15(include_dg15: bool) -> FixtureChip {
    let mrz = fixture_mrz();
    let dg1 = {
        let inner = der(0x1F, &mrz); // placeholder, replaced below
        let _ = inner;
        // 5F1F is a two-byte tag; write it manually.
        let mut content = vec![0x5F, 0x1F, 88];
        content.extend_from_slice(&mrz);
        der(0x61, &content)
    };

    let aa_key = fixture_aa_key();
    let dg15 = fixture_dg15(&aa_key);

    let dg1_hash = Sha256::digest(&dg1);
    let dg15_hash = Sha256::digest(&dg15);

    let sha256_alg = der_seq(&[der_oid("2.16.840.1.101.3.4.2.1"), der_null()]);
    let mut dg_hash_entries = vec![der_seq(&[der_int(1), der_octet(&dg1_hash)])];
    if include_dg15 {
        dg_hash_entries.push(der_seq(&[der_int(15), der_octet(&dg15_hash)]));
    }
    let lds = der_seq(&[der_int(0), sha256_alg.clone(), der_seq(&dg_hash_entries)]);

    let (dsc_cert, dsc_tbs_sha256, issuer_name) = fixture_dsc_cert();
    let csca_name_der_sha256: [u8; 32] = Sha256::digest(&issuer_name).into();

    let message_digest_attr = der_seq(&[
        der_oid("1.2.840.113549.1.9.4"),
        der_set(&[der_octet(&Sha256::digest(&lds))]),
    ]);
    let signer_info = der_seq(&[
        der_int(1),
        der_seq(&[issuer_name, der_int_bytes(&FIXTURE_DSC_SERIAL)]),
        sha256_alg.clone(),
        der(0xA0, &message_digest_attr),
        der_seq(&[der_oid("1.2.840.113549.1.1.11"), der_null()]),
        der_octet(&[0u8; 256]),
    ]);

    let signed_data = der_seq(&[
        der_int(3),
        der_set(&[sha256_alg]),
        der_seq(&[der_oid("2.23.136.1.1.1"), der(0xA0, &der_octet(&lds))]),
        der(0xA0, &dsc_cert),
        der_set(&[signer_info]),
    ]);

    let content_info = der_seq(&[der_oid("1.2.840.113549.1.7.2"), der(0xA0, &signed_data)]);
    let sod = der(0x77, &content_info);

    FixtureChip {
        sod,
        dg1,
        dg15: if include_dg15 { dg15 } else { Vec::new() },
        dsc_tbs_sha256,
        csca_name_der_sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_mrz_is_valid_td3() {
        let mrz = fixture_mrz();
        assert_eq!(&mrz[44 + 10..44 + 13], b"TWN");
        assert_eq!(&mrz[44 + 13..44 + 19], b"900101");
    }
}
