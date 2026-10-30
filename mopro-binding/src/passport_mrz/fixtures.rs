//! Test-only synthetic ICAO chip, signed for real: a test CSCA (self-signed)
//! issues a DSC certificate, the DSC signs the SOD's SignedAttributes, whose
//! messageDigest covers an LDSSecurityObject holding SHA-256(DG1). Nothing
//! here is real passport data; the verifier only trusts the test CSCA when a
//! test pins it.

#![cfg(test)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const FIXTURE_DSC_SERIAL: [u8; 5] = [0x01, 0x23, 0x45, 0x67, 0x89];
const FIXTURE_KEY_ID: [u8; 20] = [0xA1; 20];

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

pub fn der_utctime(text: &str) -> Vec<u8> {
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

/// Deterministic P-256 device key (stands in for the phone's Secure Enclave key).
pub fn fixture_device_key() -> SigningKey {
    let mut secret = [0x42u8; 32];
    secret[31] = 0x01;
    SigningKey::from_slice(&secret).expect("fixture device scalar")
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
// Certificates and chip files
// ---------------------------------------------------------------------------

const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";

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

pub fn rsa_sha256_sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    key.sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(message))
        .expect("fixture RSA signing")
}

fn sha256_with_rsa() -> Vec<u8> {
    der_seq(&[der_oid(OID_SHA256_WITH_RSA), der_null()])
}

/// One X.509 v3 certificate, sha256WithRSA-signed by `signer`.
pub struct CertSpec<'a> {
    pub serial: &'a [u8],
    pub issuer: &'a str,
    pub subject: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub subject_key: &'a RsaPrivateKey,
    pub signer: &'a RsaPrivateKey,
}

pub fn certificate(spec: &CertSpec<'_>) -> Vec<u8> {
    // AuthorityKeyIdentifier + SubjectKeyIdentifier (same fixed id: the test
    // CSCA's key id, so AKI(DSC) == SKI(CSCA)).
    let aki = der_seq(&[
        der_oid("2.5.29.35"),
        der_octet(&der_seq(&[der(0x80, &FIXTURE_KEY_ID)])),
    ]);
    let ski = der_seq(&[der_oid("2.5.29.14"), der_octet(&der_octet(&FIXTURE_KEY_ID))]);
    let tbs = der_seq(&[
        der(0xA0, &der_int(2)),
        der_int_bytes(spec.serial),
        sha256_with_rsa(),
        fixture_name(spec.issuer),
        der_seq(&[der_utctime(spec.not_before), der_utctime(spec.not_after)]),
        fixture_name(spec.subject),
        rsa_spki(spec.subject_key),
        der(0xA3, &der_seq(&[aki, ski])),
    ]);
    let signature = rsa_sha256_sign(spec.signer, &tbs);
    der_seq(&[tbs, sha256_with_rsa(), der_bitstring(&signature)])
}

pub fn csca_cert() -> Vec<u8> {
    certificate(&CertSpec {
        serial: &[0x01],
        issuer: "Fixture CSCA",
        subject: "Fixture CSCA",
        not_before: "200101000000Z",
        not_after: "450101000000Z",
        subject_key: fixture_csca_key(),
        signer: fixture_csca_key(),
    })
}

/// The DSC, issued under the test CSCA's name. `signer` is the CSCA key for
/// the genuine chain; any other key is a forged DSC claiming that issuer.
pub fn dsc_cert(signer: &RsaPrivateKey) -> Vec<u8> {
    certificate(&CertSpec {
        serial: &FIXTURE_DSC_SERIAL,
        issuer: "Fixture CSCA",
        subject: "Fixture DSC",
        not_before: "260101000000Z",
        not_after: "360101000000Z",
        subject_key: fixture_dsc_key(),
        signer,
    })
}

pub fn fixture_dg1() -> Vec<u8> {
    let mut content = vec![0x5F, 0x1F, 88];
    content.extend_from_slice(&fixture_mrz());
    der(0x61, &content)
}

/// LDSSecurityObject with DG1 and a stand-in DG2 hash (SHA-256).
pub fn lds_security_object(dg1: &[u8]) -> Vec<u8> {
    let alg = der_seq(&[der_oid(OID_SHA256), der_null()]);
    der_seq(&[
        der_int(0),
        alg,
        der_seq(&[
            der_seq(&[der_int(1), der_octet(&Sha256::digest(dg1))]),
            der_seq(&[
                der_int(2),
                der_octet(&Sha256::digest(b"fixture face image")),
            ]),
        ]),
    ])
}

/// SignedAttributes content (contentType, messageDigest), DER-sorted.
pub fn signed_attrs_content(econtent: &[u8]) -> Vec<u8> {
    let content_type = der_seq(&[
        der_oid("1.2.840.113549.1.9.3"),
        der_set(&[der_oid("2.23.136.1.1.1")]),
    ]);
    let message_digest = der_seq(&[
        der_oid("1.2.840.113549.1.9.4"),
        der_set(&[der_octet(&Sha256::digest(econtent))]),
    ]);
    [content_type, message_digest].concat()
}

/// EF.SOD around `econtent`, with `signature` over the DER SET of `attrs`.
pub fn sod(econtent: &[u8], attrs: &[u8], signature: &[u8], dsc: &[u8]) -> Vec<u8> {
    let sha256_alg = der_seq(&[der_oid(OID_SHA256), der_null()]);
    let signer_info = der_seq(&[
        der_int(1),
        der_seq(&[
            fixture_name("Fixture CSCA"),
            der_int_bytes(&FIXTURE_DSC_SERIAL),
        ]),
        sha256_alg.clone(),
        der(0xA0, attrs),
        sha256_with_rsa(),
        der_octet(signature),
    ]);
    let signed_data = der_seq(&[
        der_int(3),
        der_set(&[sha256_alg]),
        der_seq(&[der_oid("2.23.136.1.1.1"), der(0xA0, &der_octet(econtent))]),
        der(0xA0, dsc),
        der_set(&[signer_info]),
    ]);
    der(
        0x77,
        &der_seq(&[der_oid("1.2.840.113549.1.7.2"), der(0xA0, &signed_data)]),
    )
}

pub struct FixtureChip {
    pub sod: Vec<u8>,
    pub dg1: Vec<u8>,
    pub dsc_cert: Vec<u8>,
    pub csca_cert: Vec<u8>,
}

/// A chip whose SOD the DSC really signed, under a DSC the CSCA really issued.
pub fn signed_chip() -> FixtureChip {
    chip_with_dsc_signer(fixture_csca_key())
}

/// Same chip, but the DSC certificate is signed by `dsc_signer`.
pub fn chip_with_dsc_signer(dsc_signer: &RsaPrivateKey) -> FixtureChip {
    let dg1 = fixture_dg1();
    let econtent = lds_security_object(&dg1);
    let attrs = signed_attrs_content(&econtent);
    let signature = rsa_sha256_sign(fixture_dsc_key(), &der_set(&[attrs.clone()]));
    let dsc_cert = dsc_cert(dsc_signer);
    FixtureChip {
        sod: sod(&econtent, &attrs, &signature, &dsc_cert),
        dg1,
        dsc_cert,
        csca_cert: csca_cert(),
    }
}
