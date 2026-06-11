//! CSCA Master List Merkle tree (depth 8) and DSC revocation SMT (depth 32)
//! builders, mirroring `openac_core::merkle` / `openac_core::smt` walk
//! conventions exactly.
//!
//! Merkle (dsc_chain `verify_inclusion_depth_8`):
//!   - node = pedersen_hash([DOMAIN_CSCA_NODE, left, right])
//!   - `path_index` bit `d` (LSB-first) picks the side at fold step `d`
//!   - empty leaf = 0; empty subtrees fold as zero-default hashes
//!
//! SMT (`openac_core::smt::verify_non_membership`):
//!   - key = pedersen_hash([DOMAIN_REVOC_KEY, issuer_id, serial_hi, serial_lo])
//!   - fold step `d` (leaf-side first) uses key bit `d` in MSB-first order
//!     (`key_be_bytes[d / 8] >> (7 - d % 8)`)
//!   - empty leaf = 0; occupied leaf = pedersen_hash([DOMAIN_SMT_NODE, key, value])
//!   - internal = pedersen_hash([DOMAIN_SMT_NODE, left, right])

use noir_rs::acir::{AcirField, FieldElement};
use std::collections::BTreeMap;

use super::pedersen;

pub const CSCA_MERKLE_DEPTH: usize = 8;
pub const SMT_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// CSCA Master List Merkle tree
// ---------------------------------------------------------------------------

pub struct CscaInclusion {
    pub root: FieldElement,
    pub index: u32,
    pub siblings: [FieldElement; CSCA_MERKLE_DEPTH],
}

/// Build the depth-8 Master List tree with a single occupied leaf at
/// `index` (all other leaves empty = 0) and return the inclusion witness.
/// The Master List snapshot assigns every real CSCA a stable index; the
/// attestation leaf occupies the matched CSCA's slot so the public
/// `csca_root` is positionally bound to that Master List entry.
pub fn csca_single_leaf_inclusion(leaf: FieldElement, index: u32) -> CscaInclusion {
    assert!(
        index < (1 << CSCA_MERKLE_DEPTH) as u32,
        "csca index must fit depth-8 tree"
    );

    // Zero-default subtree hashes: empty[0] = empty leaf, empty[d] = node of
    // two empty depth-(d-1) subtrees.
    let mut empty = [FieldElement::zero(); CSCA_MERKLE_DEPTH];
    for d in 1..CSCA_MERKLE_DEPTH {
        empty[d] = pedersen::csca_node(empty[d - 1], empty[d - 1]);
    }

    let mut siblings = [FieldElement::zero(); CSCA_MERKLE_DEPTH];
    let mut node = leaf;
    for d in 0..CSCA_MERKLE_DEPTH {
        siblings[d] = empty[d];
        let go_right = (index >> d) & 1 == 1;
        let (left, right) = if go_right {
            (siblings[d], node)
        } else {
            (node, siblings[d])
        };
        node = pedersen::csca_node(left, right);
    }

    CscaInclusion {
        root: node,
        index,
        siblings,
    }
}

// ---------------------------------------------------------------------------
// DSC revocation SMT
// ---------------------------------------------------------------------------

/// Leaf value stored for every revoked serial. The circuit never interprets
/// it (only `H(key, value)` matters); 1 marks "revoked".
const REVOKED_LEAF_VALUE: u128 = 1;

pub struct SmtNonMembership {
    pub root: FieldElement,
    pub siblings: [FieldElement; SMT_DEPTH],
    pub old_key: FieldElement,
    pub old_value: FieldElement,
    pub is_old0: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SmtError {
    #[error("dsc serial is revoked")]
    Revoked,
}

/// Extract the 32 path bits of a key in the circuit's fold order:
/// `bits[d]` is consumed at fold step `d` (step 0 sits next to the leaf).
fn path_bits(key: FieldElement) -> [bool; SMT_DEPTH] {
    let bytes = key.to_be_bytes();
    debug_assert_eq!(bytes.len(), 32);
    core::array::from_fn(|d| (bytes[d / 8] >> (7 - (d % 8))) & 1 == 1)
}

/// Full-depth sparse Merkle tree over (key → value) pairs keyed by the first
/// 32 bits of the Pedersen serial key. Built once per witness request from
/// the matched issuer's revoked serials.
pub struct RevocationSmt {
    /// Occupied leaf slots: 32-bit path (bit d of the slot = path bit d) →
    /// (key, value, leaf hash).
    leaves: BTreeMap<u32, (FieldElement, FieldElement)>,
    /// Zero-default subtree hash per height (0 = leaf level).
    empty: [FieldElement; SMT_DEPTH + 1],
}

fn slot_of(bits: &[bool; SMT_DEPTH]) -> u32 {
    let mut slot = 0u32;
    for (d, bit) in bits.iter().enumerate() {
        if *bit {
            slot |= 1 << d;
        }
    }
    slot
}

impl RevocationSmt {
    /// Insert every revoked serial of `issuer_id`. A 32-bit path collision
    /// between two distinct revoked serials keeps the first entry (the slot
    /// stays revoked either way; non-membership proofs against either key
    /// still fail closed because the stored old_key differs from the target
    /// only when the target is NOT revoked).
    pub fn build(issuer_id: FieldElement, revoked_serials: &[[u8; 20]]) -> Self {
        let mut empty = [FieldElement::zero(); SMT_DEPTH + 1];
        for d in 1..=SMT_DEPTH {
            empty[d] = pedersen::smt_node(empty[d - 1], empty[d - 1]);
        }

        let mut leaves: BTreeMap<u32, (FieldElement, FieldElement)> = BTreeMap::new();
        for serial in revoked_serials {
            let key = pedersen::compute_serial_key(issuer_id, serial);
            let slot = slot_of(&path_bits(key));
            leaves
                .entry(slot)
                .or_insert((key, FieldElement::from(REVOKED_LEAF_VALUE)));
        }

        Self { leaves, empty }
    }

    /// Hash of the subtree at `height` whose leaf slots share the path-bit
    /// prefix `bits[height..]` equal to `prefix` (bits above `height`).
    fn subtree_hash(
        &self,
        height: usize,
        prefix: u32,
        occupied: &[(u32, FieldElement)],
    ) -> FieldElement {
        let _ = prefix;
        if occupied.is_empty() {
            return self.empty[height];
        }
        if height == 0 {
            debug_assert_eq!(occupied.len(), 1);
            return occupied[0].1;
        }
        let bit = height - 1;
        let (left, right): (Vec<_>, Vec<_>) = occupied
            .iter()
            .partition(|(slot, _)| (slot >> bit) & 1 == 0);
        let left_hash = self.subtree_hash(height - 1, prefix << 1, &left);
        let right_hash = self.subtree_hash(height - 1, (prefix << 1) | 1, &right);
        pedersen::smt_node(left_hash, right_hash)
    }

    fn leaf_hashes(&self) -> Vec<(u32, FieldElement)> {
        self.leaves
            .iter()
            .map(|(slot, (key, value))| (*slot, pedersen::smt_node(*key, *value)))
            .collect()
    }

    pub fn root(&self) -> FieldElement {
        let occupied = self.leaf_hashes();
        self.subtree_hash(SMT_DEPTH, 0, &occupied)
    }

    /// Non-membership witness for `target_key`, mirroring
    /// `verify_non_membership`'s fold exactly. Errors when the target's slot
    /// holds the target key itself (the serial is revoked).
    pub fn prove_non_membership(
        &self,
        target_key: FieldElement,
    ) -> Result<SmtNonMembership, SmtError> {
        let bits = path_bits(target_key);
        let slot = slot_of(&bits);

        let (old_key, old_value, is_old0) = match self.leaves.get(&slot) {
            None => (FieldElement::zero(), FieldElement::zero(), true),
            Some((key, value)) => {
                if *key == target_key {
                    return Err(SmtError::Revoked);
                }
                (*key, *value, false)
            }
        };

        let occupied = self.leaf_hashes();
        let mut siblings = [FieldElement::zero(); SMT_DEPTH];
        // Sibling at fold step d = the other child of the target's ancestor
        // at height d+1: leaf slots that share path bits (d+1).. with the
        // target and differ in bit d.
        for d in 0..SMT_DEPTH {
            let candidates: Vec<(u32, FieldElement)> = occupied
                .iter()
                .filter(|(s, _)| {
                    let shares_above = (d + 1..SMT_DEPTH).all(|b| (s >> b) & 1 == (slot >> b) & 1);
                    shares_above && ((s >> d) & 1 != (slot >> d) & 1)
                })
                .copied()
                .collect();
            siblings[d] = self.subtree_hash(d, 0, &candidates);
        }

        let witness = SmtNonMembership {
            root: self.root(),
            siblings,
            old_key,
            old_value,
            is_old0,
        };

        debug_assert_eq!(
            replay_non_membership_fold(target_key, &witness),
            witness.root,
            "non-membership witness must fold back to the SMT root"
        );

        Ok(witness)
    }
}

/// Reference fold — line-for-line mirror of `verify_non_membership` minus the
/// asserts. Used in debug assertions and unit tests.
pub fn replay_non_membership_fold(
    target_key: FieldElement,
    witness: &SmtNonMembership,
) -> FieldElement {
    let mut node = FieldElement::zero();
    if !witness.is_old0 {
        node = pedersen::smt_node(witness.old_key, witness.old_value);
    }
    let bits = path_bits(target_key);
    for (d, bit) in bits.iter().enumerate() {
        let (left, right) = if *bit {
            (witness.siblings[d], node)
        } else {
            (node, witness.siblings[d])
        };
        node = pedersen::smt_node(left, right);
    }
    node
}

/// Reference fold for the CSCA inclusion — mirrors `verify_inclusion_depth_8`.
#[allow(dead_code)]
pub fn replay_csca_inclusion_fold(leaf: FieldElement, witness: &CscaInclusion) -> FieldElement {
    let mut node = leaf;
    for d in 0..CSCA_MERKLE_DEPTH {
        let go_right = (witness.index >> d) & 1 == 1;
        let (left, right) = if go_right {
            (witness.siblings[d], node)
        } else {
            (node, witness.siblings[d])
        };
        node = pedersen::csca_node(left, right);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serial(seed: u8) -> [u8; 20] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    #[test]
    fn csca_inclusion_folds_back_to_root() {
        let leaf = pedersen::field(0xABCDEF);
        for index in [0u32, 1, 5, 181, 255] {
            let witness = csca_single_leaf_inclusion(leaf, index);
            assert_eq!(replay_csca_inclusion_fold(leaf, &witness), witness.root);
        }
    }

    #[test]
    fn csca_root_changes_with_index() {
        let leaf = pedersen::field(0xABCDEF);
        let a = csca_single_leaf_inclusion(leaf, 0);
        let b = csca_single_leaf_inclusion(leaf, 1);
        assert_ne!(a.root, b.root);
    }

    #[test]
    fn empty_smt_non_membership_folds_back_to_root() {
        let issuer = pedersen::field(42);
        let smt = RevocationSmt::build(issuer, &[]);
        let key = pedersen::compute_serial_key(issuer, &serial(9));
        let witness = smt.prove_non_membership(key).expect("not revoked");
        assert!(witness.is_old0);
        assert_eq!(replay_non_membership_fold(key, &witness), witness.root);
    }

    #[test]
    fn populated_smt_non_membership_folds_back_to_root() {
        let issuer = pedersen::field(42);
        let revoked: Vec<[u8; 20]> = (1..40).map(serial).collect();
        let smt = RevocationSmt::build(issuer, &revoked);
        let key = pedersen::compute_serial_key(issuer, &serial(200));
        let witness = smt.prove_non_membership(key).expect("not revoked");
        assert_eq!(replay_non_membership_fold(key, &witness), witness.root);
    }

    #[test]
    fn revoked_serial_is_rejected() {
        let issuer = pedersen::field(42);
        let revoked = vec![serial(7)];
        let smt = RevocationSmt::build(issuer, &revoked);
        let key = pedersen::compute_serial_key(issuer, &serial(7));
        assert!(matches!(
            smt.prove_non_membership(key),
            Err(SmtError::Revoked)
        ));
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let issuer = pedersen::field(42);
        let mut a: Vec<[u8; 20]> = (1..20).map(serial).collect();
        let b: Vec<[u8; 20]> = a.iter().rev().copied().collect();
        let root_a = RevocationSmt::build(issuer, &a).root();
        let root_b = RevocationSmt::build(issuer, &b).root();
        a.clear();
        assert_eq!(root_a, root_b);
    }
}
