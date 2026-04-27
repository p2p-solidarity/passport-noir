use std::hash::pedersen_hash;

use crate::commit::{DOMAIN_CSCA_LEAF, DOMAIN_CSCA_NODE};

// Fixed-depth Merkle inclusion proof for the CSCA Master List (ICAO 9303
// country signing certificate anchors). Mirrors the static-snapshot trust
// model of the Mozilla Root list used by `jwt_x5c_adapter`; see
// spec/x509-contract.md sec. 5.1.
//
// Depth is pinned to 8 (supports up to 256 CSCA entries). There are ~150
// active CSCA signers worldwide; depth 8 leaves comfortable headroom and
// keeps gate cost at ~8 * pedersen_hash_arity3 ~ 2.4k opcodes per proof.
//
// Issue P1-7 (2026-04-28):
//   * The legacy `compute_csca_leaf(modulus_limbs)` only bound the RSA
//     modulus into the leaf. An attacker who held *any* TLS-trusted cert
//     reusing the same modulus (different country / subject / validity /
//     key-usage) could replay the inclusion proof: the Master List would
//     happily accept it.
//   * `compute_csca_leaf_v2` takes a `tbs_hash` (Pedersen / SHA256 of the
//     canonical CSCA TBS, split into 128-bit hi/lo halves) and also folds
//     the RSA exponent. The off-chain Master List builder must use the
//     same recipe so on-circuit and off-circuit leaves agree.
//   * The legacy helper stays for backward-compat with existing test
//     fixtures; new flows should call `compute_csca_leaf_v2`.

pub global CSCA_MERKLE_DEPTH: u32 = 8;
pub global CSCA_MODULUS_LIMBS: u32 = 18;

/// Legacy CSCA leaf hash. Modulus-only -- prefer compute_csca_leaf_v2 for
/// new callers (P1-7, 2026-04-28).
pub fn compute_csca_leaf(csca_modulus_limbs: [u128; CSCA_MODULUS_LIMBS]) -> Field {
    let mut inputs: [Field; 19] = [0; 19];
    inputs[0] = DOMAIN_CSCA_LEAF;
    for i in 0..CSCA_MODULUS_LIMBS {
        inputs[1 + i] = csca_modulus_limbs[i] as Field;
    }
    pedersen_hash(inputs)
}

/// Issue P1-7 CSCA leaf hash. Folds the RSA exponent and a SHA256 hash of
/// the canonical CSCA TBS (country, subject, validity, key-usage, etc.)
/// into the leaf so the Merkle path commits to a true cert identity, not
/// just to the public modulus.
pub fn compute_csca_leaf_v2(
    csca_modulus_limbs: [u128; CSCA_MODULUS_LIMBS],
    rsa_exponent: u32,
    tbs_hash_hi: Field,
    tbs_hash_lo: Field,
) -> Field {
    // Layout: [DOMAIN, exponent, tbs_hi, tbs_lo, modulus_limbs[0..18]] = 22.
    let mut inputs: [Field; 22] = [0; 22];
    inputs[0] = DOMAIN_CSCA_LEAF;
    inputs[1] = rsa_exponent as Field;
    inputs[2] = tbs_hash_hi;
    inputs[3] = tbs_hash_lo;
    for i in 0..CSCA_MODULUS_LIMBS {
        inputs[4 + i] = csca_modulus_limbs[i] as Field;
    }
    pedersen_hash(inputs)
}

/// Verify a depth-8 Merkle inclusion proof against the CSCA root. The caller
/// provides the leaf hash (typically `compute_csca_leaf(modulus_limbs)`), a
/// u32 path index whose 8 low bits encode the leaf position, and the 8
/// siblings along the path (root-ward order: `siblings[0]` is the leaf's
/// immediate sibling).
pub fn verify_inclusion_depth_8(
    leaf_hash: Field,
    path_index: u32,
    siblings: [Field; CSCA_MERKLE_DEPTH],
    expected_root: Field,
) {
    // Without this check, any high bits of `path_index` beyond depth-8 are
    // silently ignored, so distinct u32 values can verify against the same
    // root -- callers outside the circuit might then pass a 9th-bit-set
    // index that looks distinct but is actually an aliased leaf position.
    assert(path_index < 256, "path_index must fit in depth-8 tree (<256)");

    let mut node = leaf_hash;

    for depth in 0..CSCA_MERKLE_DEPTH {
        let go_right = ((path_index >> depth) & 1) == 1;
        let left = if go_right { siblings[depth] } else { node };
        let right = if go_right { node } else { siblings[depth] };
        node = pedersen_hash([DOMAIN_CSCA_NODE, left, right]);
    }

    assert(node == expected_root, "CSCA Merkle root mismatch");
}

// ============================================================
// Tests
// ============================================================

fn test_modulus_limbs() -> [u128; CSCA_MODULUS_LIMBS] {
    let mut limbs: [u128; CSCA_MODULUS_LIMBS] = [0; CSCA_MODULUS_LIMBS];
    for i in 0..CSCA_MODULUS_LIMBS {
        limbs[i] = 0x1000_0000_0000_0000 + i as u128;
    }
    limbs
}

fn test_siblings() -> [Field; CSCA_MERKLE_DEPTH] {
    let mut siblings: [Field; CSCA_MERKLE_DEPTH] = [0; CSCA_MERKLE_DEPTH];
    for i in 0..CSCA_MERKLE_DEPTH {
        siblings[i] = 9999 + i as Field;
    }
    siblings
}

/// Compute the root for the fixture siblings + leaf so tests stay self-consistent
/// when the hash primitive changes.
fn test_root_for_index(index: u32) -> Field {
    let leaf = compute_csca_leaf(test_modulus_limbs());
    let siblings = test_siblings();
    let mut node = leaf;
    for depth in 0..CSCA_MERKLE_DEPTH {
        let go_right = ((index >> depth) & 1) == 1;
        let left = if go_right { siblings[depth] } else { node };
        let right = if go_right { node } else { siblings[depth] };
        node = pedersen_hash([DOMAIN_CSCA_NODE, left, right]);
    }
    node
}

#[test]
fn test_csca_inclusion_passes_at_index_zero() {
    let leaf = compute_csca_leaf(test_modulus_limbs());
    verify_inclusion_depth_8(leaf, 0, test_siblings(), test_root_for_index(0));
}

#[test]
fn test_csca_inclusion_passes_at_other_index() {
    // Different path index must still verify when paired with its matching root.
    let leaf = compute_csca_leaf(test_modulus_limbs());
    let index: u32 = 181; // 0b1011_0101 path pattern
    verify_inclusion_depth_8(leaf, index, test_siblings(), test_root_for_index(index));
}

#[test(should_fail)]
fn test_csca_inclusion_rejects_wrong_root() {
    let leaf = compute_csca_leaf(test_modulus_limbs());
    let mut bad_root = test_root_for_index(0);
    bad_root += 1;
    verify_inclusion_depth_8(leaf, 0, test_siblings(), bad_root);
}

#[test(should_fail)]
fn test_csca_inclusion_rejects_tampered_leaf() {
    let mut limbs = test_modulus_limbs();
    limbs[0] ^= 1;
    let tampered_leaf = compute_csca_leaf(limbs);
    verify_inclusion_depth_8(tampered_leaf, 0, test_siblings(), test_root_for_index(0));
}

#[test(should_fail)]
fn test_csca_inclusion_rejects_out_of_range_path_index() {
    // path_index >= 256 must be rejected; depth-8 tree only has indices 0..255.
    let leaf = compute_csca_leaf(test_modulus_limbs());
    verify_inclusion_depth_8(leaf, 256, test_siblings(), test_root_for_index(0));
}

#[test(should_fail)]
fn test_csca_inclusion_rejects_high_bit_aliased_index() {
    // Flip bit 8 (256) only; if range check is missing this would alias to index 0
    // and verify against the same root, silently accepting a forged position.
    let leaf = compute_csca_leaf(test_modulus_limbs());
    verify_inclusion_depth_8(leaf, 0x100, test_siblings(), test_root_for_index(0));
}

#[test]
fn test_csca_leaf_v2_separates_from_v1() {
    // P1-7: even with zero TBS hash + matching exponent, v2 layout uses
    // arity-22 pedersen_hash vs. v1's arity-19, so the two leaves cannot
    // collide. This keeps the Master List builder honest: every CSCA
    // entry committed under v1 stays distinct from v2 entries.
    let v1 = compute_csca_leaf(test_modulus_limbs());
    let v2 = compute_csca_leaf_v2(test_modulus_limbs(), 65537, 0, 0);
    assert(v1 != v2, "compute_csca_leaf_v2 must be domain-separated from v1");
}

#[test]
fn test_csca_leaf_v2_changes_with_tbs_hash() {
    // P1-7: changing the TBS hash (which encodes country, subject,
    // validity, key usage) must move the leaf. Otherwise the Master List
    // would accept any cert that shares a modulus, regardless of identity.
    let a = compute_csca_leaf_v2(test_modulus_limbs(), 65537, 0, 0);
    let b = compute_csca_leaf_v2(test_modulus_limbs(), 65537, 1, 0);
    assert(a != b, "compute_csca_leaf_v2 must bind tbs_hash_hi");
    let c = compute_csca_leaf_v2(test_modulus_limbs(), 65537, 0, 1);
    assert(a != c, "compute_csca_leaf_v2 must bind tbs_hash_lo");
}

#[test]
fn test_csca_leaf_v2_changes_with_exponent() {
    // P1-7: an attacker who held a CSCA-equivalent cert with the same
    // modulus + TBS hash but a different RSA exponent (e.g., 3 vs 65537)
    // must not collide with the legitimate Master List entry.
    let a = compute_csca_leaf_v2(test_modulus_limbs(), 65537, 0, 0);
    let b = compute_csca_leaf_v2(test_modulus_limbs(), 3, 0, 0);
    assert(a != b, "compute_csca_leaf_v2 must bind RSA exponent");
}
