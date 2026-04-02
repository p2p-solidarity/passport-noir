use std::hash::pedersen_commitment;
use std::embedded_curve_ops::EmbeddedCurvePoint;

// Domain separators for credential types
// Each credential adapter uses a unique domain to prevent cross-type commitment collisions
pub global DOMAIN_PASSPORT: Field = 0x01;
pub global DOMAIN_SDJWT: Field = 0x02;
pub global DOMAIN_MDL: Field = 0x03;

// Paper: Com(m; r) = product(g_i^{m_i}) * h^r
// Noir: pedersen_commitment([domain, attrs..., r]) -> EmbeddedCurvePoint (Grumpkin)
//
// Properties:
//   - Computationally binding (discrete log hardness on Grumpkin)
//   - Perfectly hiding (randomness link_rand masks message)
//   - Homomorphic: C' = C + delta_r * H (enables out-of-circuit re-randomization)

/// Compute a Pedersen commitment over credential attributes.
/// Generic for any credential type (passport, SD-JWT, mDL, etc.).
///
/// The commitment binds to:
///   - credential_type: domain separator preventing cross-type collisions
///   - attr_hash_hi/lo: 256-bit standardized attribute hash as 2 Field elements
///   - link_rand: blinding randomness for hiding and re-randomization
pub fn commit_attributes(
    credential_type: Field,
    attr_hash_hi: Field,
    attr_hash_lo: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    pedersen_commitment([credential_type, attr_hash_hi, attr_hash_lo, link_rand])
}

/// Extended commitment that includes additional attribute fields.
/// Used when the show circuit needs to bind predicates to specific attributes
/// beyond the 256-bit hash (e.g., individual claim fields for SD-JWT).
pub fn commit_attributes_extended(
    credential_type: Field,
    attr_hash_hi: Field,
    attr_hash_lo: Field,
    extra_0: Field,
    extra_1: Field,
    extra_2: Field,
    extra_3: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    pedersen_commitment([
        credential_type,
        attr_hash_hi,
        attr_hash_lo,
        extra_0,
        extra_1,
        extra_2,
        extra_3,
        link_rand,
    ])
}

/// Assert that a computed commitment matches the expected public output coordinates.
/// Convert a [u8; 32] hash to two Field elements (128-bit each, big-endian split).
/// Standardizes any 256-bit hash into the (hi, lo) format used by commit_attributes.
pub fn hash_to_fields(hash: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + hash[i] as Field;
        lo = lo * 256 + hash[16 + i] as Field;
    }
    (hi, lo)
}

/// Used by both prepare and show circuits to enforce commitment equality.
pub fn assert_commitment_eq(
    commitment: EmbeddedCurvePoint,
    expected_x: Field,
    expected_y: Field,
) {
    assert(commitment.x == expected_x, "Commitment X mismatch");
    assert(commitment.y == expected_y, "Commitment Y mismatch");
}

// ============================================================
// Tests
// ============================================================

#[test]
fn test_commit_deterministic() {
    let c1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c2 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    assert(c1.x == c2.x);
    assert(c1.y == c2.y);
}

#[test]
fn test_commit_changes_with_randomness() {
    let c1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c2 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 43);
    assert(c1.x != c2.x);
}

#[test]
fn test_commit_domain_separation() {
    let c_passport = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c_sdjwt = commit_attributes(DOMAIN_SDJWT, 100, 200, 42);
    assert(c_passport.x != c_sdjwt.x);
}

#[test]
fn test_commit_changes_with_attrs() {
    let c1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c2 = commit_attributes(DOMAIN_PASSPORT, 101, 200, 42);
    assert(c1.x != c2.x);
}

#[test]
fn test_assert_commitment_eq_passes() {
    let c = commit_attributes(DOMAIN_PASSPORT, 10, 20, 30);
    assert_commitment_eq(c, c.x, c.y);
}

#[test(should_fail)]
fn test_assert_commitment_eq_fails_on_mismatch() {
    let c = commit_attributes(DOMAIN_PASSPORT, 10, 20, 30);
    assert_commitment_eq(c, c.x + 1, c.y);
}

#[test]
fn test_extended_commit_deterministic() {
    let c1 = commit_attributes_extended(DOMAIN_SDJWT, 1, 2, 3, 4, 5, 6, 99);
    let c2 = commit_attributes_extended(DOMAIN_SDJWT, 1, 2, 3, 4, 5, 6, 99);
    assert(c1.x == c2.x);
    assert(c1.y == c2.y);
}

#[test]
fn test_extended_commit_differs_from_basic() {
    let c_basic = commit_attributes(DOMAIN_SDJWT, 1, 2, 99);
    let c_ext = commit_attributes_extended(DOMAIN_SDJWT, 1, 2, 3, 4, 5, 6, 99);
    assert(c_basic.x != c_ext.x);
}
