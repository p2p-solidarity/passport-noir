use std::hash::pedersen_hash;

use crate::commit::DOMAIN_SMT_NODE;

// OpenAC revocation Sparse Merkle Tree primitive.
//
// Shared by `jwt_x5c_adapter` (X.509 DSC cert serial) and `passport_adapter`
// (passport DSC serial). Path A v3.1 standardises:
//   - Depth 32 (serial_number[0..4] big-endian key)
//   - Internal nodes: pedersen_hash([DOMAIN_SMT_NODE, left, right])
//   - Off-circuit snapshot tooling must use the same primitives (see
//     spec/x509-contract.md sec. 5.2).
//
// The 2^32 keyspace covers Google OIDC / ICAO issuance volumes for the
// foreseeable future. Upgrades that need more keyspace should introduce a
// new depth-N variant; depth stability keeps verifier snapshots compatible.

/// SMT depth; keep in lock-step with `SERIAL_KEY_BYTES` (= DEPTH / 8).
pub global SMT_DEPTH: u32 = 32;

/// Bytes of `serial_number` consumed as path key. Must equal `SMT_DEPTH / 8`.
pub global SERIAL_KEY_BYTES: u32 = 4;

/// Internal-node hash. arity-3 pedersen_hash separates the SMT output space
/// from arity-2 / arity-5 pedersen_hash uses elsewhere (profile derivations,
/// pk_digest) via `DOMAIN_SMT_NODE`.
pub fn hash_field_pair(left: Field, right: Field) -> Field {
    pedersen_hash([DOMAIN_SMT_NODE, left, right])
}

pub fn smt_fold(node: Field, sibling: Field, go_right: bool) -> Field {
    let left = if go_right { sibling } else { node };
    let right = if go_right { node } else { sibling };
    hash_field_pair(left, right)
}

/// Derive the SMT key from the first `SERIAL_KEY_BYTES` of an X.509-style
/// serial number (big-endian). `verify_non_membership` walks
/// `serial[depth / 8]` and only accesses the same leading bytes, so this
/// key must mirror the walk; shortening or extending it would silently
/// decouple the non-membership check from the SMT path.
pub fn compute_serial_key(serial_number: [u8; 20]) -> Field {
    let mut key: Field = 0;
    for i in 0..SERIAL_KEY_BYTES {
        key = key * 256 + serial_number[i] as Field;
    }
    key
}

/// SMT non-membership proof for a 20-byte X.509 serial number.
///
/// `smt_is_old0 = true` means the target key falls into an empty slot and no
/// previous-key witness is required. Otherwise `smt_old_key / smt_old_value`
/// represent the closest occupied leaf; it must differ from the target key
/// to prove non-membership.
pub fn verify_non_membership(
    serial_number: [u8; 20],
    smt_siblings: [Field; SMT_DEPTH],
    smt_old_key: Field,
    smt_old_value: Field,
    smt_is_old0: bool,
    smt_root: Field,
) {
    let target_key = compute_serial_key(serial_number);
    let mut node: Field = 0;

    if !smt_is_old0 {
        assert(smt_old_key != target_key, "Revocation witness matches blocked serial");
        node = hash_field_pair(smt_old_key, smt_old_value);
    }

    for depth in 0..SMT_DEPTH {
        let byte = serial_number[depth / 8];
        let shift: u8 = 7 - ((depth % 8) as u8);
        let go_right = ((byte >> shift) & 1) == 1;
        node = smt_fold(node, smt_siblings[depth], go_right);
    }

    assert(node == smt_root, "Revocation SMT root mismatch");
}

// ============================================================
// Tests
// ============================================================

/// Reference test fixture: deterministic siblings + canonical serial.
/// Mirrors the historical fixture that shipped inline in jwt_x5c_adapter.
fn test_serial_number() -> [u8; 20] {
    [1, 35, 69, 103, 137, 171, 205, 239, 254, 220, 186, 152, 118, 84, 50, 16, 202, 254, 186, 190]
}

fn test_siblings() -> [Field; SMT_DEPTH] {
    let mut siblings: [Field; SMT_DEPTH] = [0; SMT_DEPTH];
    for i in 0..SMT_DEPTH {
        siblings[i] = 123456 + i as Field;
    }
    siblings
}

/// Recompute the SMT root that matches `test_siblings()` with `smt_is_old0 = true`.
/// Computed in-circuit so it tracks any change to `hash_field_pair` automatically.
fn test_root() -> Field {
    let siblings = test_siblings();
    let serial = test_serial_number();
    let mut node: Field = 0;
    for depth in 0..SMT_DEPTH {
        let byte = serial[depth / 8];
        let shift: u8 = 7 - ((depth % 8) as u8);
        let go_right = ((byte >> shift) & 1) == 1;
        node = smt_fold(node, siblings[depth], go_right);
    }
    node
}

#[test]
fn test_non_membership_passes_for_valid_witness() {
    verify_non_membership(test_serial_number(), test_siblings(), 0, 0, true, test_root());
}

#[test]
fn test_compute_serial_key_uses_first_four_bytes() {
    let serial = test_serial_number();
    let key = compute_serial_key(serial);
    // 0x01 << 24 | 0x23 << 16 | 0x45 << 8 | 0x67 = 0x01234567
    assert(key == 0x01234567, "serial_key must pack first 4 bytes big-endian");
}

#[test(should_fail)]
fn test_non_membership_fails_on_wrong_root() {
    let mut bad_root = test_root();
    bad_root += 1;
    verify_non_membership(test_serial_number(), test_siblings(), 0, 0, true, bad_root);
}

#[test(should_fail)]
fn test_non_membership_rejects_matching_old_key() {
    let target_key = compute_serial_key(test_serial_number());
    // Supplying the target key as old_key with is_old0 = false must fail.
    verify_non_membership(test_serial_number(), test_siblings(), target_key, 0, false, test_root());
}
