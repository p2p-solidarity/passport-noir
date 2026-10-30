use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::{digest, sha256_var};
use std::hash::pedersen_hash;

use openac_core::commit::hash_to_fields;
use openac_core::device::verify_device_binding;
use openac_core::predicate::{check_age_above, two_digit_year_to_four};
use openac_core::show::compute_passport_nullifier;

// Passport MRZ endorsement + device binding (passport-noir 0.5.0).
//
// One circuit over the chip's REAL ICAO 9303 bytes -- no app-normalised
// layout, no self-minted CSCA/DSC (the <= 0.4.0 trust gap, SECURITY.md):
//   1. The DSC's RSA-2048 PKCS#1 v1.5 SHA-256 signature verifies over the
//      CMS SignedAttributes (DER, SET tag 0x31).
//   2. SignedAttributes' messageDigest attribute = SHA-256(eContent), where
//      eContent is the LDSSecurityObject.
//   3. The LDSSecurityObject's DataGroupHash for DG1 = SHA-256(DG1).
//      Steps 1-3 are "the issuing state's DSC endorses this MRZ".
//   4. The device key signed the verifier's challenge; the output device tag
//      is a per-scope pseudonym of that key (not transferable without it).
//   5. Age / nationality are read only from the endorsed DG1.
//
// The DSC modulus is PUBLIC. The verifier checks, outside the circuit, that
// the DSC certificate carrying that modulus chains to a pinned CSCA, is
// valid today and is not revoked. Without that check this proof says nothing
// about any state -- anyone can mint a DSC.
//
// Supported: TD3 passports (93-byte DG1), SHA-256 LDS hashes, SHA-256 CMS
// digest, RSA-2048 DSC with e = 65537. Anything else fails to prove.

global DG1_LEN: u32 = 93;
// LDSSecurityObject with all 16 DG hashes at SHA-256 is ~660 bytes.
global MAX_ECONTENT: u32 = 768;
// contentType + signingTime + messageDigest (+ room for one more attribute).
global MAX_SIGNED_ATTRS: u32 = 256;
global RSA_LIMB_COUNT: u32 = 18;
global DSC_RSA_EXPONENT: u32 = 65537;

// DG1 = 61 5B { 5F1F 58 <88 MRZ chars> } for TD3.
global DG1_HEADER: [u8; 5] = [0x61, 0x5B, 0x5F, 0x1F, 0x58];
// MRZ line 2 starts at DG1[5 + 44]; ICAO 9303-4 field positions in line 2.
global LINE2: u32 = 49;
global NATIONALITY_AT: u32 = LINE2 + 10;
global BIRTH_AT: u32 = LINE2 + 13;
global EXPIRY_AT: u32 = LINE2 + 21;

// DataGroupHash ::= SEQUENCE { dataGroupNumber INTEGER (1), OCTET STRING (32) }
global DG1_HASH_PREFIX: [u8; 7] = [0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
// Attribute ::= SEQUENCE { id-messageDigest, SET { OCTET STRING (32) } }
global MESSAGE_DIGEST_PREFIX: [u8; 17] = [
    0x30, 0x2F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x31, 0x22, 0x04,
    0x20,
];

/// Domain separator for the scoped device tag. ASCII "devt".
global DOMAIN_DEVICE_TAG: Field = 0x64657674;

/// Assert `prefix || value` sits at `haystack[at - P .. at + 32]`, inside `len`.
fn assert_tagged_hash_at<let N: u32, let P: u32>(
    haystack: [u8; N],
    len: u32,
    at: u32,
    prefix: [u8; P],
    value: [u8; 32],
) {
    assert(at >= P, "Hash offset before its DER prefix");
    assert(at + 32 <= len, "Hash offset past the signed bytes");
    for k in 0..P {
        assert(haystack[at - P + k] == prefix[k], "DER prefix mismatch");
    }
    for k in 0..32 {
        assert(haystack[at + k] == value[k], "Signed hash mismatch");
    }
}

fn digit(b: u8) -> u32 {
    assert((b >= 48) & (b <= 57), "MRZ date is not numeric");
    (b - 48) as u32
}

/// (YY, MM, DD) of a 6-digit MRZ date at `dg1[at..at + 6]`.
fn mrz_date(dg1: [u8; DG1_LEN], at: u32) -> (u32, u32, u32) {
    (
        digit(dg1[at]) * 10 + digit(dg1[at + 1]), digit(dg1[at + 2]) * 10 + digit(dg1[at + 3]),
        digit(dg1[at + 4]) * 10 + digit(dg1[at + 5]),
    )
}

/// Per-scope pseudonym of the device key.
fn device_tag(pk_digest: Field, scope: Field) -> Field {
    pedersen_hash([DOMAIN_DEVICE_TAG, pk_digest, scope])
}

fn main(
    // === Chip bytes (private) ===
    dg1: [u8; DG1_LEN],
    econtent: [u8; MAX_ECONTENT],
    econtent_len: u32,
    dg1_hash_offset: u32,
    signed_attrs: [u8; MAX_SIGNED_ATTRS],
    signed_attrs_len: u32,
    message_digest_offset: u32,
    signature_limbs: [u128; RSA_LIMB_COUNT],
    redc_limbs: [u128; RSA_LIMB_COUNT],
    // === Device binding (private) ===
    device_pk_x: [u8; 32],
    device_pk_y: [u8; 32],
    device_signature: [u8; 64],
    // === Public: the DSC that signed (the verifier chains it to a pinned CSCA) ===
    dsc_modulus_limbs: pub [u128; RSA_LIMB_COUNT],
    // === Public: verifier-chosen request ===
    challenge: pub [u8; 32],
    scope: pub Field,
    today: pub u32,
    min_age: pub u32,
    disclose_nationality: pub bool,
) -> pub (bool, [u8; 3], Field, Field) {
    assert(econtent_len <= MAX_ECONTENT, "eContent too long");
    assert(signed_attrs_len <= MAX_SIGNED_ATTRS, "SignedAttributes too long");
    for k in 0..5 {
        assert(dg1[k] == DG1_HEADER[k], "DG1 is not a TD3 MRZ");
    }

    // 1. DSC -> SignedAttributes. CMS signs the DER SET (tag 0x31), not the
    //    [0] IMPLICIT form stored in SignerInfo.
    assert(signed_attrs[0] == 0x31, "SignedAttributes must be DER SET encoded");
    let attrs_hash = sha256_var(signed_attrs, signed_attrs_len);
    let params: BigNumParams<RSA_LIMB_COUNT, 2048> =
        BigNumParams::new(false, dsc_modulus_limbs, redc_limbs);
    let signature: RuntimeBigNum<RSA_LIMB_COUNT, 2048> =
        RuntimeBigNum { params, limbs: signature_limbs };
    assert(
        verify_sha256_pkcs1v15(attrs_hash, signature, DSC_RSA_EXPONENT),
        "DSC signature over SignedAttributes does not verify",
    );

    // 2. SignedAttributes -> eContent.
    let econtent_hash = sha256_var(econtent, econtent_len);
    assert_tagged_hash_at(
        signed_attrs,
        signed_attrs_len,
        message_digest_offset,
        MESSAGE_DIGEST_PREFIX,
        econtent_hash,
    );

    // 3. eContent -> DG1.
    let dg1_hash: [u8; 32] = digest(dg1);
    assert_tagged_hash_at(
        econtent,
        econtent_len,
        dg1_hash_offset,
        DG1_HASH_PREFIX,
        dg1_hash,
    );

    // 4. Device binding.
    let pk_digest = verify_device_binding(device_pk_x, device_pk_y, device_signature, challenge);
    let tag = device_tag(pk_digest, scope);

    // 5. Claims from the endorsed MRZ. `today` is YYYYMMDD, pinned by the verifier.
    let today_year = today / 10000;
    let today_month = (today / 100) % 100;
    let today_day = today % 100;
    let (ey, em, ed) = mrz_date(dg1, EXPIRY_AT);
    assert((2000 + ey) * 10000 + em * 100 + ed >= today, "Passport has expired");

    let (by, bm, bd) = mrz_date(dg1, BIRTH_AT);
    // A birth year after this year's YY is last century.
    let birth_year = two_digit_year_to_four(by, today_year % 100 + 1);
    let age_ok = if min_age == 0 {
        false
    } else {
        check_age_above(
            birth_year,
            bm,
            bd,
            today_year,
            today_month,
            today_day,
            min_age,
        )
    };
    let nationality = if disclose_nationality {
        [dg1[NATIONALITY_AT], dg1[NATIONALITY_AT + 1], dg1[NATIONALITY_AT + 2]]
    } else {
        [0, 0, 0]
    };

    // Per-passport nullifier keyed on H(eContent), which covers every DG hash
    // (face image included), so it cannot be recomputed from the MRZ alone.
    // The issuing state CAN compute it (it holds the SOD). Scope 0 -> 0.
    let (md_hi, md_lo) = hash_to_fields(econtent_hash);
    let nullifier = if scope == 0 {
        0
    } else {
        compute_passport_nullifier(md_hi, md_lo, scope)
    };

    (age_ok, nationality, tag, nullifier)
}

// ============================================================
// Tests (pure helpers; the full chain is tested from Rust against
// synthetic ICAO fixtures signed by a test CSCA)
// ============================================================

#[test]
fn test_mrz_date_parses_digits() {
    let mut dg1: [u8; DG1_LEN] = [0x3C; DG1_LEN];
    let date = "900101".as_bytes();
    for i in 0..6 {
        dg1[BIRTH_AT + i] = date[i];
    }
    let (y, m, d) = mrz_date(dg1, BIRTH_AT);
    assert((y == 90) & (m == 1) & (d == 1));
}

#[test(should_fail_with = "MRZ date is not numeric")]
fn test_mrz_date_rejects_filler() {
    let dg1: [u8; DG1_LEN] = [0x3C; DG1_LEN];
    let _ = mrz_date(dg1, BIRTH_AT);
}

#[test]
fn test_tagged_hash_found_at_offset() {
    let mut buf: [u8; 64] = [0; 64];
    let value: [u8; 32] = [7; 32];
    for k in 0..7 {
        buf[10 + k] = DG1_HASH_PREFIX[k];
    }
    for k in 0..32 {
        buf[17 + k] = 7;
    }
    assert_tagged_hash_at(buf, 49, 17, DG1_HASH_PREFIX, value);
}

#[test(should_fail_with = "DER prefix mismatch")]
fn test_tagged_hash_needs_its_der_prefix() {
    let mut buf: [u8; 64] = [0; 64];
    for k in 0..32 {
        buf[17 + k] = 7;
    }
    assert_tagged_hash_at(buf, 49, 17, DG1_HASH_PREFIX, [7; 32]);
}

#[test(should_fail_with = "Hash offset past the signed bytes")]
fn test_tagged_hash_must_be_inside_the_signed_length() {
    let mut buf: [u8; 64] = [0; 64];
    for k in 0..7 {
        buf[10 + k] = DG1_HASH_PREFIX[k];
    }
    for k in 0..32 {
        buf[17 + k] = 7;
    }
    assert_tagged_hash_at(buf, 48, 17, DG1_HASH_PREFIX, [7; 32]);
}

#[test]
fn test_device_tag_differs_by_scope() {
    assert(device_tag(1, 2) != device_tag(1, 3));
}
