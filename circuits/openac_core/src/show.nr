use std::hash::pedersen_hash;

// Show-phase verification (v3.1 -- unified across credential types).
//
// v3.1 protocol change (2026-06-10, spec/upgrade-plan-v3.1.md sec.3.1):
// the in-circuit challenge digest was REMOVED. Freshness / replay protection
// is carried entirely by `nonce_hash`, which is
//   * a public input of every show circuit (pinned by the verifier against
//     the nonce it issued for this session), and
//   * the ECDSA-P256 message verified by `device::verify_device_binding`,
//     so the enclave signature and the commitment opening are already bound
//     to the same session value by the proof system itself.
// UltraHonk binds all public inputs into the proof transcript, so an extra
// in-circuit digest over (nonce, commitment, epoch) added no security and
// cost two SHA256 blocks per presentation on the mobile hot path.
//
// The pre-v3.1 SHA256 construction (the v2 show digest domain) is RETIRED;
// cross-layer-check.sh guards against the literal domain string reappearing
// in this file. Verifiers that want an audit-trail transcript digest compute
// it off-circuit.

/// Byte length of the verifier-issued nonce hash (SHA256 output).
pub global HASH_LEN: u32 = 32;

/// Domain separator for the scoped link tag. ASCII "ltag". Moved from
/// profile.nr (v3 kept two incompatible tag constructions; v3.1 unifies on
/// this one -- see HIGH-4, 2026-06-10).
global DOMAIN_LINK_TAG: Field = 0x6c746167;

/// Compute the scoped link tag -- ONE construction for every credential type.
///
/// tag = pedersen_hash([DOMAIN_LINK_TAG, credential_type, link_rand, link_scope, epoch])
///
/// Keying on `link_rand` (not the commitment coordinates) keeps the tag
/// stable under out-of-circuit commitment re-randomization, and including
/// `credential_type` gives explicit per-credential namespace separation
/// instead of relying on pedersen arity differences (HIGH-4 fix).
pub fn compute_link_tag(
    credential_type: Field,
    link_rand: Field,
    link_scope: Field,
    epoch: Field,
) -> Field {
    pedersen_hash(
        [DOMAIN_LINK_TAG, credential_type, link_rand, link_scope, epoch],
    )
}

/// Link tag with explicit unlinkable-mode support: `link_mode == false`
/// forces the tag to 0 so callers cannot emit a tag while claiming to be
/// unlinkable. Callers must also pin `link_scope == 0` (verify_show does).
pub fn compute_link_tag_with_mode(
    credential_type: Field,
    link_rand: Field,
    link_scope: Field,
    epoch: Field,
    link_mode: bool,
) -> Field {
    if link_mode {
        compute_link_tag(credential_type, link_rand, link_scope, epoch)
    } else {
        0
    }
}

/// Show-phase link verification shared by ALL credential types (v3.1).
///
/// Linkable mode: recomputes the scoped tag and asserts it matches the
/// public output. Unlinkable mode: pins both scope and tag to zero so a
/// prover cannot smuggle a session context while claiming unlinkability.
pub fn verify_show(
    credential_type: Field,
    link_rand: Field,
    link_mode: bool,
    link_scope: Field,
    epoch: Field,
    expected_link_tag: Field,
) {
    if link_mode {
        let tag = compute_link_tag(credential_type, link_rand, link_scope, epoch);
        assert(tag == expected_link_tag, "Scoped link tag mismatch");
    } else {
        assert(link_scope == 0, "Unlinkable mode requires zero scope");
        assert(expected_link_tag == 0, "Unlinkable mode requires zero tag");
    }
}

// ============================================================
// Tests
// ============================================================

global TEST_DOMAIN_A: Field = 0x01;
global TEST_DOMAIN_B: Field = 0x02;

#[test]
fn test_link_tag_deterministic() {
    let t1 = compute_link_tag(TEST_DOMAIN_A, 10, 30, 40);
    let t2 = compute_link_tag(TEST_DOMAIN_A, 10, 30, 40);
    assert(t1 == t2, "Link tag should be deterministic");
}

#[test]
fn test_link_tag_differs_across_scope() {
    let t1 = compute_link_tag(TEST_DOMAIN_A, 10, 30, 40);
    let t2 = compute_link_tag(TEST_DOMAIN_A, 10, 31, 40);
    assert(t1 != t2, "Different scope must produce different tag");
}

#[test]
fn test_link_tag_differs_across_epoch() {
    let t1 = compute_link_tag(TEST_DOMAIN_A, 10, 30, 40);
    let t2 = compute_link_tag(TEST_DOMAIN_A, 10, 30, 41);
    assert(t1 != t2, "Different epoch must produce different tag");
}

#[test]
fn test_link_tag_differs_across_link_rand() {
    let t1 = compute_link_tag(TEST_DOMAIN_A, 10, 30, 40);
    let t2 = compute_link_tag(TEST_DOMAIN_A, 11, 30, 40);
    assert(t1 != t2, "Different link_rand must produce different tag");
}

#[test]
fn test_link_tag_namespace_separated_by_credential_type() {
    // HIGH-4 (v3.1): tag namespaces are separated by an EXPLICIT
    // credential_type input, not by pedersen arity side effects. The same
    // holder secret under two credential domains must yield distinct tags.
    let t_a = compute_link_tag(TEST_DOMAIN_A, 10, 30, 40);
    let t_b = compute_link_tag(TEST_DOMAIN_B, 10, 30, 40);
    assert(t_a != t_b, "Different credential_type must produce different tag");
}

#[test]
fn test_link_tag_with_mode_unlinkable_returns_zero() {
    let tag = compute_link_tag_with_mode(TEST_DOMAIN_A, 123, 456, 789, false);
    assert(tag == 0, "Unlinkable mode must yield zero link tag");
}

#[test]
fn test_link_tag_with_mode_linkable_matches_compute_link_tag() {
    let with_mode = compute_link_tag_with_mode(TEST_DOMAIN_A, 123, 456, 789, true);
    let direct = compute_link_tag(TEST_DOMAIN_A, 123, 456, 789);
    assert(with_mode == direct, "Linkable mode must match compute_link_tag");
}

#[test]
fn test_verify_show_linkable_mode() {
    let scope: Field = 42;
    let epoch: Field = 0x20260401;
    let tag = compute_link_tag(TEST_DOMAIN_A, 77, scope, epoch);
    verify_show(TEST_DOMAIN_A, 77, true, scope, epoch, tag);
}

#[test]
fn test_verify_show_unlinkable_mode() {
    verify_show(TEST_DOMAIN_A, 77, false, 0, 0x20260401, 0);
}

#[test(should_fail_with = "Scoped link tag mismatch")]
fn test_verify_show_fails_on_tampered_tag() {
    let scope: Field = 42;
    let epoch: Field = 0x20260401;
    let tag = compute_link_tag(TEST_DOMAIN_A, 77, scope, epoch);
    verify_show(TEST_DOMAIN_A, 77, true, scope, epoch, tag + 1);
}

#[test(should_fail_with = "Scoped link tag mismatch")]
fn test_verify_show_fails_on_cross_domain_tag_replay() {
    // v3.1 digest-removal regression: a tag computed under credential type A
    // must not satisfy a presentation claiming credential type B.
    let scope: Field = 42;
    let epoch: Field = 0x20260401;
    let tag_a = compute_link_tag(TEST_DOMAIN_A, 77, scope, epoch);
    verify_show(TEST_DOMAIN_B, 77, true, scope, epoch, tag_a);
}

#[test(should_fail_with = "Unlinkable mode requires zero scope")]
fn test_verify_show_fails_unlinkable_with_nonzero_scope() {
    verify_show(TEST_DOMAIN_A, 77, false, 42, 0x20260401, 0);
}

#[test(should_fail_with = "Unlinkable mode requires zero tag")]
fn test_verify_show_fails_unlinkable_with_nonzero_tag() {
    verify_show(TEST_DOMAIN_A, 77, false, 0, 0x20260401, 99);
}
