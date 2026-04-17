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

pub global CSCA_MERKLE_DEPTH: u32 = 8;
pub global CSCA_MODULUS_LIMBS: u32 = 18;

/// Compress an 18-limb RSA-2048 modulus into a single Field leaf hash so
/// that CSCA Merkle paths only need to carry one `Field` per node. The
/// domain separator guarantees that this arity-19 pedersen_hash output
/// cannot collide with any other arity-19 pedersen_hash use (there are
/// none today, but the constant makes future additions safe by default).
pub fn compute_csca_leaf(csca_modulus_limbs: [u128; CSCA_MODULUS_LIMBS]) -> Field {
    let mut inputs: [Field; 19] = [0; 19];
    inputs[0] = DOMAIN_CSCA_LEAF;
    for i in 0..CSCA_MODULUS_LIMBS {
        inputs[1 + i] = csca_modulus_limbs[i] as Field;
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
    let index: u32 = 181;  // 0b1011_0101 path pattern
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
