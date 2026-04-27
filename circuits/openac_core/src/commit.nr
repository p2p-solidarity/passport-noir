use std::embedded_curve_ops::EmbeddedCurvePoint;
use std::hash::pedersen_commitment;

// Domain separators for credential types
// Each credential adapter uses a unique domain to prevent cross-type commitment collisions
pub global DOMAIN_PASSPORT: Field = 0x01;
pub global DOMAIN_X509: Field = 0x02;
pub global DOMAIN_SDJWT: Field = 0x03;
pub global DOMAIN_MDL: Field = 0x04;

// Domain separator for SMT internal-node pedersen_hash folds. ASCII "smt1".
// Required so that arity-3 pedersen_hash([DOMAIN_SMT_NODE, left, right]) used by
// revocation SMT verifiers cannot collide with other pedersen_hash outputs in the
// same constraint system (e.g. DOMAIN_PK_DIGEST in device.nr). Follows the same
// explicit-domain pattern used elsewhere in this library.
pub global DOMAIN_SMT_NODE: Field = 0x736d7431;

// Issue P1-6 (2026-04-28): revocation-list SMT key derivation domain
// (ASCII "rkey"). Used by openac_core::smt::compute_serial_key to bind both
// issuer identity and the full 20-byte serial into the SMT path key, so a
// non-membership proof under one issuer can never be replayed against
// another issuer's snapshot.
pub global DOMAIN_REVOC_KEY: Field = 0x726b6579;

// Issue P1-7 (2026-04-28): canonical issuer-identity domain. The CSCA /
// X.509 trust roots used to commit the leaf as `pedersen_hash([leaf_modulus
// limbs])`, which only bound the RSA modulus -- not country, subject,
// validity, key-usage, or even the RSA exponent. compute_x509_issuer_id
// (openac_core::smt) folds these into a single Field so the Merkle leaf is
// a true cert identity hash.
pub global DOMAIN_X509_ISSUER: Field = 0x78353039;

// CSCA Master List Merkle tree domain separators. ASCII "cscn" / "cscl".
// Internal-node hash uses DOMAIN_CSCA_NODE (arity-3). Leaf pre-image uses
// DOMAIN_CSCA_LEAF with the 18 RSA modulus limbs to derive a single Field
// leaf_hash. Separate from DOMAIN_SMT_NODE so that the CSCA inclusion tree and
// the revocation SMT cannot share nodes even if a future variant uses the same
// depth / arity.
pub global DOMAIN_CSCA_NODE: Field = 0x6373636e;
pub global DOMAIN_CSCA_LEAF: Field = 0x6373636c;

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

/// Path A v3 commitment: binds an enclave public-key digest into the Pedersen
/// commitment so that the show circuit can enforce in-circuit ECDSA-P256 device
/// binding without a separate device-binding proof.
///
/// pk_digest is expected to be Poseidon/Pedersen hash of the enclave pk (x, y)
/// coordinates split into 128-bit hi/lo Field elements. The openac_core::device
/// module provides helpers to produce this value.
///
/// Domain separation is provided by `credential_type`. The arity (5) differs
/// from commit_attributes (4) and commit_attributes_extended (8), so
/// commitments across versions are non-malleable.
pub fn commit_attributes_v3(
    credential_type: Field,
    attr_hash_hi: Field,
    attr_hash_lo: Field,
    pk_digest: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    pedersen_commitment(
        [credential_type, attr_hash_hi, attr_hash_lo, pk_digest, link_rand],
    )
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
pub fn assert_commitment_eq(commitment: EmbeddedCurvePoint, expected_x: Field, expected_y: Field) {
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
    assert(c1.x == c2.x, "Commitment X should be deterministic");
    assert(c1.y == c2.y, "Commitment Y should be deterministic");
}

#[test]
fn test_commit_changes_with_randomness() {
    let c1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c2 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 43);
    assert(c1.x != c2.x, "Different randomness must produce different commitment");
}

#[test]
fn test_commit_domain_separation() {
    let c_passport = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c_x509 = commit_attributes(DOMAIN_X509, 100, 200, 42);
    let c_sdjwt = commit_attributes(DOMAIN_SDJWT, 100, 200, 42);
    assert(c_passport.x != c_x509.x, "Different domains must produce different commitments");
    assert(c_x509.x != c_sdjwt.x, "Different domains must produce different commitments");
}

#[test]
fn test_commit_changes_with_attrs_hi() {
    let c1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c2 = commit_attributes(DOMAIN_PASSPORT, 101, 200, 42);
    assert(c1.x != c2.x, "Different attr_hi must produce different commitment");
}

#[test]
fn test_commit_changes_with_attrs_lo() {
    let c1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c2 = commit_attributes(DOMAIN_PASSPORT, 100, 201, 42);
    assert(c1.x != c2.x, "Different attr_lo must produce different commitment");
}

#[test]
fn test_assert_commitment_eq_passes() {
    let c = commit_attributes(DOMAIN_PASSPORT, 10, 20, 30);
    assert_commitment_eq(c, c.x, c.y);
}

#[test(should_fail)]
fn test_assert_commitment_eq_fails_on_x_mismatch() {
    let c = commit_attributes(DOMAIN_PASSPORT, 10, 20, 30);
    assert_commitment_eq(c, c.x + 1, c.y);
}

#[test(should_fail)]
fn test_assert_commitment_eq_fails_on_y_mismatch() {
    let c = commit_attributes(DOMAIN_PASSPORT, 10, 20, 30);
    assert_commitment_eq(c, c.x, c.y + 1);
}

#[test]
fn test_hash_to_fields_deterministic() {
    let hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let (hi1, lo1) = hash_to_fields(hash);
    let (hi2, lo2) = hash_to_fields(hash);
    assert(hi1 == hi2, "hash_to_fields hi should be deterministic");
    assert(lo1 == lo2, "hash_to_fields lo should be deterministic");
}

#[test]
fn test_hash_to_fields_splits_correctly() {
    let mut hash: [u8; 32] = [0; 32];
    hash[0] = 1;
    hash[16] = 2;
    let (hi, lo) = hash_to_fields(hash);
    assert(hi != 0, "hash_to_fields hi should be non-zero when first byte set");
    assert(lo != 0, "hash_to_fields lo should be non-zero when 17th byte set");
    assert(hi != lo, "hi and lo should differ for asymmetric input");
}

// ---------- commit_attributes_v3 (Path A) tests ----------

#[test]
fn test_commit_v3_deterministic() {
    let c1 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7777, 42);
    let c2 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7777, 42);
    assert(c1.x == c2.x, "v3 commitment X should be deterministic");
    assert(c1.y == c2.y, "v3 commitment Y should be deterministic");
}

#[test]
fn test_commit_v3_domain_separation() {
    let c_passport = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7777, 42);
    let c_x509 = commit_attributes_v3(DOMAIN_X509, 100, 200, 7777, 42);
    let c_sdjwt = commit_attributes_v3(DOMAIN_SDJWT, 100, 200, 7777, 42);
    assert(c_passport.x != c_x509.x, "v3 different domains must produce different commitments");
    assert(c_x509.x != c_sdjwt.x, "v3 different domains must produce different commitments");
}

#[test]
fn test_commit_v3_changes_with_pk_digest() {
    let c1 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7777, 42);
    let c2 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7778, 42);
    assert(c1.x != c2.x, "v3 different pk_digest must produce different commitment");
}

#[test]
fn test_commit_v3_changes_with_link_rand() {
    let c1 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7777, 42);
    let c2 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 7777, 43);
    assert(c1.x != c2.x, "v3 different link_rand must produce different commitment");
}

#[test]
fn test_commit_v3_differs_from_v1() {
    // Arity differs (5 vs 4), so even with zero pk_digest the commitments must
    // be distinct -- this is what prevents cross-version malleability.
    let c_v1 = commit_attributes(DOMAIN_PASSPORT, 100, 200, 42);
    let c_v3 = commit_attributes_v3(DOMAIN_PASSPORT, 100, 200, 0, 42);
    assert(c_v1.x != c_v3.x, "v3 commitment must differ from v1 even with zero pk_digest");
}
