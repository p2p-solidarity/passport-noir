use std::hash::pedersen_hash;

use crate::commit::hash_to_fields;

pub global MAX_DOMAIN_LEN: u32 = 31;
pub global TARGET_DOMAIN_LEN: u32 = 64;

pub global SALT_X509: Field = 0x78353039;
pub global SALT_SDJWT: Field = 0x73646a77;

// Per-scope link_rand derivation domain. ASCII "scrd" (scope rand). Phase 6
// follow-up / spec sec.7.1: each verifier scope gets its own credential
// commitment so colluding verifiers cannot correlate the holder by the
// commitment coordinates. Instead of the app picking an arbitrary link_rand
// per scope, the prepare circuit DERIVES it from a single holder seed + the
// public scope, so (a) the holder regenerates the same per-scope commitment
// from one secret, and (b) the verifier pins `link_scope` and is cryptographic-
// ally sure the commitment is the holder's pseudonym for THAT scope (a reused
// cross-scope commitment can no longer pass).
pub global SALT_SCOPE_RAND: Field = 0x73637264;

// v3.1 (2026-06-10, spec/upgrade-plan-v3.1.md):
//   * compute_link_challenge_digest / compute_show_challenge_digest_v2 /
//     compute_composite_challenge_digest were DELETED -- the in-circuit
//     challenge digest is retired; freshness rides on the pinned public
//     `nonce_hash` (see openac_core::show header).
//   * compute_link_tag / compute_link_tag_with_mode moved to
//     openac_core::show with a unified, credential_type-keyed construction.
//   * pack_passport_profile / unpack_passport_profile were replaced by
//     pack_passport_claims / unpack_passport_claims: the full-width SOD and
//     DG1 hashes now enter the passport commitment as their own Pedersen
//     inputs (commit::commit_passport_v3_1) instead of being truncated to
//     11 / 12 bytes inside a shared 32-byte pack.

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

/// Derive a per-scope blinding value from one holder seed + the verifier scope
/// (spec sec.7.1). Binding the scope in-circuit makes the resulting commitment
/// a scope-specific pseudonym: a different `link_scope` yields a different
/// commitment, so verifiers cannot correlate the holder across scopes by the
/// committed coordinates, yet the holder needs to store only `link_rand_seed`.
pub fn derive_scoped_link_rand(link_rand_seed: Field, link_scope: Field) -> Field {
    pedersen_hash([SALT_SCOPE_RAND, link_rand_seed, link_scope])
}

pub fn derive_x509_link_rand(link_rand_p: Field) -> Field {
    pedersen_hash([link_rand_p, SALT_X509])
}

pub fn derive_sdjwt_link_rand(link_rand_p: Field) -> Field {
    pedersen_hash([link_rand_p, SALT_SDJWT])
}

/// Pack the disclosed-predicate passport claims into one Field (9 bytes,
/// big-endian): birth_year(4) || birth_month(1) || birth_day(1) ||
/// nationality(3). Credential fingerprints (SOD / DG1 hashes) are NOT part
/// of this value in v3.1 -- they are separate full-width commitment inputs.
pub fn pack_passport_claims(
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    nationality: [u8; 3],
) -> Field {
    assert(birth_month < 256, "Birth month must fit in one byte");
    assert(birth_day < 256, "Birth day must fit in one byte");

    (birth_year as Field) * 1099511627776 // 2^40
        + (birth_month as Field) * 4294967296 // 2^32
        + (birth_day as Field) * 16777216 // 2^24
        + (nationality[0] as Field) * 65536
        + (nationality[1] as Field) * 256
        + (nationality[2] as Field)
}

/// Inverse of `pack_passport_claims`. `to_be_bytes::<9>` range-constrains the
/// claims Field to 72 bits, so a prover cannot smuggle extra high-order data
/// past the unpack.
pub fn unpack_passport_claims(claims: Field) -> (u32, u32, u32, [u8; 3]) {
    let b = claims.to_be_bytes::<9>();
    let birth_year: u32 =
        (b[0] as u32) * 16777216 + (b[1] as u32) * 65536 + (b[2] as u32) * 256 + (b[3] as u32);
    let nationality = [b[6], b[7], b[8]];
    (birth_year, b[4] as u32, b[5] as u32, nationality)
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
fn test_passport_claims_roundtrip() {
    let claims = pack_passport_claims(2000, 3, 15, [84, 87, 78]);
    let (birth_year, birth_month, birth_day, nationality) = unpack_passport_claims(claims);

    assert(birth_year == 2000, "Birth year should round-trip through packed passport claims");
    assert(birth_month == 3, "Birth month should round-trip through packed passport claims");
    assert(birth_day == 15, "Birth day should round-trip through packed passport claims");
    assert(nationality[0] == 84, "Nationality should round-trip through packed passport claims");
    assert(nationality[1] == 87, "Nationality should round-trip through packed passport claims");
    assert(nationality[2] == 78, "Nationality should round-trip through packed passport claims");
}

#[test]
fn test_passport_claims_distinct_dates_distinct_fields() {
    let a = pack_passport_claims(2000, 3, 15, [84, 87, 78]);
    let b = pack_passport_claims(2000, 3, 16, [84, 87, 78]);
    let c = pack_passport_claims(2000, 3, 15, [85, 83, 65]);
    assert(a != b, "Different birth day must pack to a different claims Field");
    assert(a != c, "Different nationality must pack to a different claims Field");
}

#[test(should_fail_with = "Birth month must fit in one byte")]
fn test_passport_claims_rejects_oversized_month() {
    let _ = pack_passport_claims(2000, 256, 15, [84, 87, 78]);
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

#[test(should_fail)]
fn test_pack_x509_domain_rejects_oversized_input() {
    let domain: [u8; MAX_DOMAIN_LEN] = [1; MAX_DOMAIN_LEN];
    let _ = pack_x509_domain(domain, 32);
}

#[test]
fn test_derive_link_rands_are_domain_separated() {
    let x509 = derive_x509_link_rand(777);
    let sdjwt = derive_sdjwt_link_rand(777);
    assert(x509 != sdjwt, "X.509 and SD-JWT link_rand derivations must differ");
}

#[test]
fn test_scoped_link_rand_deterministic() {
    let a = derive_scoped_link_rand(12345, 99);
    let b = derive_scoped_link_rand(12345, 99);
    assert(a == b, "scoped link_rand must be deterministic for the same seed + scope");
}

#[test]
fn test_scoped_link_rand_changes_with_scope() {
    // Core unlinkability property (sec.7.1): the same holder seed under two
    // verifier scopes must produce different blinding -> different commitments.
    let s1 = derive_scoped_link_rand(12345, 99);
    let s2 = derive_scoped_link_rand(12345, 100);
    assert(s1 != s2, "different scope must produce different scoped link_rand");
}

#[test]
fn test_scoped_link_rand_changes_with_seed() {
    let a = derive_scoped_link_rand(12345, 99);
    let b = derive_scoped_link_rand(54321, 99);
    assert(a != b, "different seed must produce different scoped link_rand");
}

#[test]
fn test_scoped_link_rand_domain_separated_from_credential_derivations() {
    // Distinct domain + arity keeps the scope derivation from colliding with
    // the per-credential link_rand derivations.
    let scoped = derive_scoped_link_rand(777, 0);
    let x509 = derive_x509_link_rand(777);
    assert(scoped != x509, "scoped link_rand must differ from x509 link_rand derivation");
}
