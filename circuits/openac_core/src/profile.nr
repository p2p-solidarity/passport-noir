use std::hash::pedersen_hash;

use crate::commit::hash_to_fields;

pub global MAX_DOMAIN_LEN: u32 = 31;
pub global TARGET_DOMAIN_LEN: u32 = 64;

pub global SALT_X509: Field = 0x78353039;
pub global SALT_SDJWT: Field = 0x73646a77;

global CHALLENGE_DOMAIN: Field = 0x63686c67;
global LINK_TAG_DOMAIN: Field = 0x6c746167;

pub fn fields_to_bytes32(hi: Field, lo: Field) -> [u8; 32] {
    let hi_bytes = hi.to_be_bytes::<16>();
    let lo_bytes = lo.to_be_bytes::<16>();
    let mut out: [u8; 32] = [0; 32];

    for i in 0..16 {
        out[i] = hi_bytes[i];
        out[16 + i] = lo_bytes[i];
    }

    out
}

pub fn derive_x509_link_rand(link_rand_p: Field) -> Field {
    pedersen_hash([link_rand_p, SALT_X509])
}

pub fn derive_sdjwt_link_rand(link_rand_p: Field) -> Field {
    pedersen_hash([link_rand_p, SALT_SDJWT])
}

pub fn compute_link_challenge_digest(nonce_hash: [u8; 32], link_rand: Field) -> Field {
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    pedersen_hash([CHALLENGE_DOMAIN, nonce_hi, nonce_lo, link_rand])
}

pub fn compute_link_tag(link_rand: Field, link_scope: Field, epoch: Field) -> Field {
    pedersen_hash([LINK_TAG_DOMAIN, link_rand, link_scope, epoch])
}

/// Issue P1-9 (2026-04-28): commitment-bound challenge digest used by
/// x509_show / composite_show. Folding the credential commitment into the
/// transcript prevents a presentation from being replayed against a
/// different credential (same nonce, same scope) -- the audit flagged this
/// as a missing binding in the previous Pedersen-based show circuits.
pub fn compute_show_challenge_digest_v2(
    nonce_hash: [u8; 32],
    commitment_x: Field,
    commitment_y: Field,
    link_rand: Field,
) -> Field {
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    pedersen_hash(
        [CHALLENGE_DOMAIN, nonce_hi, nonce_lo, commitment_x, commitment_y, link_rand],
    )
}

/// Issue P1-9: commitment-bound challenge digest for composite presentations
/// (passport + aux). Both commitments are folded into the transcript so a
/// composite presentation under one credential bundle can never be replayed
/// against a different bundle.
pub fn compute_composite_challenge_digest(
    nonce_hash: [u8; 32],
    passport_commitment_x: Field,
    passport_commitment_y: Field,
    aux_commitment_x: Field,
    aux_commitment_y: Field,
    link_rand_p: Field,
) -> Field {
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    pedersen_hash([
        CHALLENGE_DOMAIN,
        nonce_hi,
        nonce_lo,
        passport_commitment_x,
        passport_commitment_y,
        aux_commitment_x,
        aux_commitment_y,
        link_rand_p,
    ])
}

/// Issue P1-9 (2026-04-28): scoped link tag with explicit unlinkable-mode
/// support. When `link_mode == false` the tag is forced to 0 and the caller
/// must also pin link_scope == 0 (mirroring openac_core::show::verify_show).
/// This is the first place where x509_show / composite_show can emit a 0
/// tag; previously they always published a tag, so the verifier had to
/// trust off-chain metadata for the unlinkable case.
pub fn compute_link_tag_with_mode(
    link_rand: Field,
    link_scope: Field,
    epoch: Field,
    link_mode: bool,
) -> Field {
    if link_mode {
        compute_link_tag(link_rand, link_scope, epoch)
    } else {
        0
    }
}

pub fn pack_passport_profile(
    sod_hash: [u8; 32],
    dg1_hash: [u8; 32],
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    nationality: [u8; 3],
) -> (Field, Field) {
    let mut packed: [u8; 32] = [0; 32];
    packed[0] = ((birth_year >> 24) & 0xFF) as u8;
    packed[1] = ((birth_year >> 16) & 0xFF) as u8;
    packed[2] = ((birth_year >> 8) & 0xFF) as u8;
    packed[3] = (birth_year & 0xFF) as u8;
    packed[4] = birth_month as u8;
    packed[5] = birth_day as u8;
    packed[6] = nationality[0];
    packed[7] = nationality[1];
    packed[8] = nationality[2];

    for i in 0..12 {
        packed[9 + i] = dg1_hash[i];
    }

    for i in 0..11 {
        packed[21 + i] = sod_hash[i];
    }

    hash_to_fields(packed)
}

pub fn unpack_passport_profile(attr_hi: Field, attr_lo: Field) -> (u32, u32, u32, [u8; 3]) {
    let packed = fields_to_bytes32(attr_hi, attr_lo);
    let birth_year: u32 = (packed[0] as u32) * 16777216
        + (packed[1] as u32) * 65536
        + (packed[2] as u32) * 256
        + (packed[3] as u32);
    let nationality = [packed[6], packed[7], packed[8]];
    (birth_year, packed[4] as u32, packed[5] as u32, nationality)
}

pub fn pack_x509_domain(domain_bytes: [u8; MAX_DOMAIN_LEN], domain_len: u8) -> (Field, Field) {
    assert(domain_len as u32 <= MAX_DOMAIN_LEN, "Packed X.509 domain length exceeds maximum");

    let mut packed: [u8; 32] = [0; 32];
    packed[0] = domain_len;

    for i in 0..MAX_DOMAIN_LEN {
        packed[1 + i] = domain_bytes[i];
    }

    hash_to_fields(packed)
}

pub fn unpack_x509_domain(attr_hi: Field, attr_lo: Field) -> ([u8; MAX_DOMAIN_LEN], u32) {
    let packed = fields_to_bytes32(attr_hi, attr_lo);
    let mut domain_bytes: [u8; MAX_DOMAIN_LEN] = [0; MAX_DOMAIN_LEN];

    for i in 0..MAX_DOMAIN_LEN {
        domain_bytes[i] = packed[1 + i];
    }

    (domain_bytes, packed[0] as u32)
}

#[test]
fn test_passport_profile_roundtrip() {
    let sod_hash: [u8; 32] = [0xAA; 32];
    let dg1_hash: [u8; 32] = [0xBB; 32];
    let (attr_hi, attr_lo) = pack_passport_profile(sod_hash, dg1_hash, 2000, 3, 15, [84, 87, 78]);
    let (birth_year, birth_month, birth_day, nationality) =
        unpack_passport_profile(attr_hi, attr_lo);

    assert(birth_year == 2000, "Birth year should round-trip through packed passport attrs");
    assert(birth_month == 3, "Birth month should round-trip through packed passport attrs");
    assert(birth_day == 15, "Birth day should round-trip through packed passport attrs");
    assert(nationality[0] == 84, "Nationality should round-trip through packed passport attrs");
    assert(nationality[1] == 87, "Nationality should round-trip through packed passport attrs");
    assert(nationality[2] == 78, "Nationality should round-trip through packed passport attrs");
}

#[test]
fn test_x509_domain_roundtrip() {
    let mut domain: [u8; MAX_DOMAIN_LEN] = [0; MAX_DOMAIN_LEN];
    domain[0] = 110;
    domain[1] = 116;
    domain[2] = 117;
    domain[3] = 46;
    domain[4] = 101;
    domain[5] = 100;
    domain[6] = 117;
    domain[7] = 46;
    domain[8] = 116;
    domain[9] = 119;
    let (attr_hi, attr_lo) = pack_x509_domain(domain, 10);
    let (decoded, len) = unpack_x509_domain(attr_hi, attr_lo);

    assert(len == 10, "X.509 domain length should round-trip");
    assert(decoded[0] == 110, "Packed X.509 domain should retain ASCII content");
    assert(decoded[9] == 119, "Packed X.509 domain should retain trailing bytes");
}

#[test]
fn test_link_challenge_digest_changes_with_nonce() {
    let digest_a = compute_link_challenge_digest([1; 32], 42);
    let digest_b = compute_link_challenge_digest([2; 32], 42);
    assert(digest_a != digest_b, "Challenge digest must change when the nonce hash changes");
}

#[test(should_fail)]
fn test_pack_x509_domain_rejects_oversized_input() {
    let domain: [u8; MAX_DOMAIN_LEN] = [1; MAX_DOMAIN_LEN];
    let _ = pack_x509_domain(domain, 32);
}

#[test]
fn test_show_challenge_digest_v2_changes_with_commitment() {
    let a = compute_show_challenge_digest_v2([1; 32], 100, 200, 42);
    let b = compute_show_challenge_digest_v2([1; 32], 101, 200, 42);
    assert(a != b, "Folding the commitment must change the challenge digest");
}

#[test]
fn test_show_challenge_digest_v2_changes_with_nonce() {
    let a = compute_show_challenge_digest_v2([1; 32], 100, 200, 42);
    let b = compute_show_challenge_digest_v2([2; 32], 100, 200, 42);
    assert(a != b, "Different nonce must change the challenge digest");
}

#[test]
fn test_composite_challenge_digest_separates_from_v2() {
    // Composite digest must differ from v2 even when c_aux is zero -- the
    // arity-8 vs. arity-6 pedersen_hash form already gives separation, so
    // adapters cannot accidentally swap the two helpers.
    let v2 = compute_show_challenge_digest_v2([1; 32], 100, 200, 42);
    let composite = compute_composite_challenge_digest([1; 32], 100, 200, 0, 0, 42);
    assert(v2 != composite, "Composite digest must be domain-separated from v2");
}

#[test]
fn test_compute_link_tag_with_mode_unlinkable_returns_zero() {
    // Issue P1-9: unlinkable mode forces the tag to 0 inside the helper so
    // x509_show / composite_show callers cannot accidentally emit a non-zero
    // tag while the verifier policy says "unlinkable".
    let tag = compute_link_tag_with_mode(123, 456, 789, false);
    assert(tag == 0, "Unlinkable mode must yield zero link tag");
}

#[test]
fn test_compute_link_tag_with_mode_linkable_matches_compute_link_tag() {
    let with_mode = compute_link_tag_with_mode(123, 456, 789, true);
    let direct = compute_link_tag(123, 456, 789);
    assert(with_mode == direct, "Linkable mode must match compute_link_tag");
}
