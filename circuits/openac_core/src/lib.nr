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
/// Provides: commit_attributes, commit_attributes_v3, assert_commitment_eq
/// Domain constants: DOMAIN_PASSPORT, DOMAIN_SDJWT, DOMAIN_MDL
pub mod commit;

/// Path A in-circuit device binding helpers.
/// Provides: verify_device_binding (ECDSA-P256 + pk_digest), pk_digest_from_bytes.
pub mod device;

/// Show-phase operations: challenge binding and scoped linking.
/// Paper: C2 show relation -- binds verifier challenge and optional scope.
/// Provides: compute_challenge_digest, compute_link_tag, verify_show
pub mod show;

/// Generic predicate functions over credential attributes.
/// Paper: f_i(m_1, ..., m_n) = p_i
/// Provides: check_age_above, check_bytes3_eq, two_digit_year_to_four
pub mod predicate;

/// Shared profile encodings and device-link derivations for multi-credential flows.
/// Provides: passport/x509 packing, device-link derivation, link tag helpers.
pub mod profile;

/// Revocation Sparse Merkle Tree primitive shared across issuer adapters.
/// Provides: verify_non_membership, compute_serial_key, hash_field_pair,
/// smt_fold, SMT_DEPTH, SERIAL_KEY_BYTES.
pub mod smt;

/// Fixed-depth Merkle inclusion primitive for CSCA Master List anchors.
/// Provides: verify_inclusion_depth_8, compute_csca_leaf.
pub mod merkle;

/// Base64url encoder / decoder (RFC 4648 sec. 5, no padding) shared by the
/// SD-JWT and JWT-X5C adapters so disclosure-hash inclusion proofs and
/// JWS signing-input <-> normalized-payload bindings can both happen
/// in-circuit. Closes audit issues P0-5 and P1-4 (2026-04-28).
pub mod base64;
