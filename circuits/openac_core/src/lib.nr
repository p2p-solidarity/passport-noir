// OpenAC Core Library
//
// Generic building blocks for the OpenAC anonymous credential framework.
// These modules are credential-type agnostic and shared by all adapters
// (passport, SD-JWT, mDL, etc.).
//
// Paper reference: "OpenAC: Open Design for Transparent and Lightweight Anonymous Credentials"
// Architecture: modular AC framework where "issuer-signature verification, attribute commitment,
// predicate proofs, and device binding are defined as separate modules with clear interfaces."

/// Pedersen commitment on Grumpkin curve.
/// Paper: Com(m; r) = product(g_i^{m_i}) * h^r
/// Provides: commit_attributes, commit_attributes_extended, assert_commitment_eq
/// Domain constants: DOMAIN_PASSPORT, DOMAIN_SDJWT, DOMAIN_MDL
pub mod commit;

/// Show-phase operations: challenge binding and scoped linking.
/// Paper: C2 show relation -- binds verifier challenge and optional scope.
/// Provides: compute_challenge_digest, compute_link_tag, verify_show
pub mod show;

/// Generic predicate functions over credential attributes.
/// Paper: f_i(m_1, ..., m_n) = p_i
/// Provides: check_age_above, check_bytes3_eq, two_digit_year_to_four
pub mod predicate;
