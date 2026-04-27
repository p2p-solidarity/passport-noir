use std::hash::pedersen_hash;

use crate::commit::{DOMAIN_REVOC_KEY, DOMAIN_SMT_NODE};

// OpenAC revocation Sparse Merkle Tree primitive.
//
// Shared by `jwt_x5c_adapter` (X.509 DSC cert serial) and `passport_adapter`
// (passport DSC serial). Path A v3.1 standardises:
//   - Depth 32 (4 leading bytes of `target_key` -- a Pedersen hash of issuer
//     identity + the FULL 20-byte serial, see compute_serial_key below).
//   - Internal nodes: pedersen_hash([DOMAIN_SMT_NODE, left, right])
//   - Off-circuit snapshot tooling must use the same primitives (see
//     spec/x509-contract.md sec. 5.2).
//
// Issue P1-6 (2026-04-28):
//   * The previous version derived the SMT key as `serial_number[0..4]`,
//     so an attacker who held a revoked cert with serial X could pass any
//     non-revoked serial that *agreed in the leading 4 bytes* and pass the
//     non-membership check. Worse, the key did not bind the issuer at all,
//     so a non-membership proof produced under issuer A could be replayed
//     against issuer B's snapshot.
//   * The fix: the SMT key is now `pedersen_hash([DOMAIN_REVOC_KEY,
//     issuer_id, serial_hi, serial_lo])` where `serial_hi/lo` cover all 20
//     bytes of the X.509 serial. The walk uses the first `SMT_DEPTH` bits of
//     this hash, so 32-bit collisions still happen but only across keys
//     that share both the same issuer AND a colliding 32-bit hash prefix --
//     this is effectively a 32-bit per-issuer keyspace, not a 32-bit per
//     leading-serial-bytes keyspace.
//   * Callers (passport_adapter, jwt_x5c_adapter) compute `issuer_id` from
//     a canonical issuer identity hash (see compute_csca_leaf and the new
//     compute_x509_issuer_id helper) and bind it both into the SMT key and
//     into the prepare proof's public inputs. Verifiers can then assert
//     that the off-chain SMT snapshot used to build smt_root was for the
//     same issuer the proof committed to.

/// SMT depth; keep in lock-step with `SERIAL_KEY_BYTES` (= DEPTH / 8).
pub global SMT_DEPTH: u32 = 32;

/// Bytes of `serial_number` consumed as path key. Must equal `SMT_DEPTH / 8`.
pub global SERIAL_KEY_BYTES: u32 = 4;

/// Number of bytes in the 20-byte X.509 serial split into two Field halves.
/// 16 + 4 = 20, matching the size of the standard X.509 / ICAO serial.
pub global SERIAL_HI_BYTES: u32 = 16;
pub global SERIAL_LO_BYTES: u32 = 4;

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

/// Pack a 20-byte serial into `(serial_hi, serial_lo)` for use in
/// `compute_serial_key`. `serial_hi` covers bytes 0..15, `serial_lo` covers
/// bytes 16..19. Splitting into two Fields keeps each value < 2^128, well
/// inside the bn254 scalar range, so callers can recompute the same key
/// off-circuit without a special big-int reducer.
pub fn pack_serial(serial_number: [u8; 20]) -> (Field, Field) {
    let mut hi: Field = 0;
    for i in 0..SERIAL_HI_BYTES {
        hi = hi * 256 + serial_number[i] as Field;
    }
    let mut lo: Field = 0;
    for i in 0..SERIAL_LO_BYTES {
        lo = lo * 256 + serial_number[SERIAL_HI_BYTES + i] as Field;
    }
    (hi, lo)
}

/// Derive the SMT key for a (issuer, full-serial) pair. The key is a Pedersen
/// hash so the SMT path uses the *first SMT_DEPTH bits of the hash*, not the
/// leading bytes of the serial. This closes the P1-6 gap where two distinct
/// serials sharing the leading 4 bytes (same issuer or different) would
/// collide in the SMT path and let a revoked cert smuggle a non-membership
/// proof through.
pub fn compute_serial_key(issuer_id: Field, serial_number: [u8; 20]) -> Field {
    let (serial_hi, serial_lo) = pack_serial(serial_number);
    pedersen_hash([DOMAIN_REVOC_KEY, issuer_id, serial_hi, serial_lo])
}

/// Convert a Field to its 32 big-endian bytes for path-bit extraction.
fn field_to_be_bytes_32(f: Field) -> [u8; 32] {
    f.to_be_bytes::<32>()
}

/// SMT non-membership proof for a (issuer, 20-byte serial) pair.
///
/// `smt_is_old0 = true` means the target key falls into an empty slot and no
/// previous-key witness is required. Otherwise `smt_old_key / smt_old_value`
/// represent the closest occupied leaf; it must differ from the target key
/// to prove non-membership.
///
/// `issuer_id` is a Field that uniquely identifies the issuer whose
/// revocation list this proof targets. Off-chain SMT snapshot tooling MUST
/// build the SMT keyed on the same `issuer_id`, otherwise the in-circuit
/// path walk diverges from the snapshot and verification fails.
pub fn verify_non_membership(
    issuer_id: Field,
    serial_number: [u8; 20],
    smt_siblings: [Field; SMT_DEPTH],
    smt_old_key: Field,
    smt_old_value: Field,
    smt_is_old0: bool,
    smt_root: Field,
) {
    let target_key = compute_serial_key(issuer_id, serial_number);
    let mut node: Field = 0;

    if !smt_is_old0 {
        assert(smt_old_key != target_key, "Revocation witness matches blocked serial");
        node = hash_field_pair(smt_old_key, smt_old_value);
    }

    // Walk bits of the hashed key (not the raw serial). This is the core
    // P1-6 fix: collisions now require finding two distinct (issuer, serial)
    // pairs whose hashed keys agree on the leading SMT_DEPTH bits, i.e. a
    // 32-bit second-preimage on a Pedersen hash output -- rather than two
    // serials that just happen to share leading bytes.
    let key_bytes = field_to_be_bytes_32(target_key);
    for depth in 0..SMT_DEPTH {
        let byte = key_bytes[depth / 8];
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

fn test_issuer_id() -> Field {
    // Arbitrary fixed Field for the smt unit tests. Real callers compute it
    // from a canonical issuer identity hash (see compute_csca_leaf and
    // compute_x509_issuer_id below).
    0x49535355_45525f5453544944
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
    let key = compute_serial_key(test_issuer_id(), test_serial_number());
    let key_bytes = field_to_be_bytes_32(key);
    let mut node: Field = 0;
    for depth in 0..SMT_DEPTH {
        let byte = key_bytes[depth / 8];
        let shift: u8 = 7 - ((depth % 8) as u8);
        let go_right = ((byte >> shift) & 1) == 1;
        node = smt_fold(node, siblings[depth], go_right);
    }
    node
}

#[test]
fn test_non_membership_passes_for_valid_witness() {
    verify_non_membership(
        test_issuer_id(),
        test_serial_number(),
        test_siblings(),
        0,
        0,
        true,
        test_root(),
    );
}

#[test]
fn test_compute_serial_key_binds_full_serial_and_issuer() {
    // P1-6: changing any byte of the serial OR the issuer must change the key.
    let issuer_a = test_issuer_id();
    let issuer_b = test_issuer_id() + 1;
    let serial_a = test_serial_number();
    let mut serial_b = test_serial_number();
    serial_b[19] ^= 0x01; // last byte -- unreachable by the old prefix-only scheme

    let key_a = compute_serial_key(issuer_a, serial_a);
    let key_b = compute_serial_key(issuer_a, serial_b);
    let key_c = compute_serial_key(issuer_b, serial_a);

    assert(
        key_a != key_b,
        "Serial last byte must affect the key (closes prefix-only collision gap)",
    );
    assert(key_a != key_c, "Issuer change must affect the key (closes cross-issuer replay gap)");
}

#[test(should_fail)]
fn test_non_membership_fails_on_wrong_root() {
    let mut bad_root = test_root();
    bad_root += 1;
    verify_non_membership(
        test_issuer_id(),
        test_serial_number(),
        test_siblings(),
        0,
        0,
        true,
        bad_root,
    );
}

#[test(should_fail)]
fn test_non_membership_rejects_matching_old_key() {
    let target_key = compute_serial_key(test_issuer_id(), test_serial_number());
    // Supplying the target key as old_key with is_old0 = false must fail.
    verify_non_membership(
        test_issuer_id(),
        test_serial_number(),
        test_siblings(),
        target_key,
        0,
        false,
        test_root(),
    );
}

#[test(should_fail)]
fn test_non_membership_rejects_wrong_issuer() {
    // P1-6: a non-membership proof produced under issuer A must NOT verify
    // when replayed against an SMT snapshot built for issuer B (the path
    // walk diverges because the key changes).
    let other_issuer = test_issuer_id() + 0xdeadbeef;
    verify_non_membership(
        other_issuer,
        test_serial_number(),
        test_siblings(),
        0,
        0,
        true,
        test_root(),
    );
}

/// P1-7 helper: compress an X.509 issuer cert identity into a single Field.
/// Folds modulus + RSA exponent + canonical TBS hash so the Merkle leaf used
/// by jwt_x5c_adapter / passport_adapter binds the full cert identity, not
/// just the modulus. Off-circuit Master List builders must use the same
/// recipe.
pub fn compute_x509_issuer_id(
    issuer_modulus_limbs: [u128; 18],
    rsa_exponent: u32,
    tbs_hash_hi: Field,
    tbs_hash_lo: Field,
) -> Field {
    // pedersen_hash arity is bounded; lay this out as
    // [DOMAIN, exponent, tbs_hi, tbs_lo, modulus_limbs[0..18]] = 22 inputs.
    let mut inputs: [Field; 22] = [0; 22];
    inputs[0] = crate::commit::DOMAIN_X509_ISSUER;
    inputs[1] = rsa_exponent as Field;
    inputs[2] = tbs_hash_hi;
    inputs[3] = tbs_hash_lo;
    for i in 0..18 {
        inputs[4 + i] = issuer_modulus_limbs[i] as Field;
    }
    pedersen_hash(inputs)
}

#[test]
fn test_compute_x509_issuer_id_changes_with_exponent() {
    // P1-7: the Merkle leaf must move when the cert's RSA exponent changes,
    // so an attacker who swaps a 65537 cert for an e=3 cert with the same
    // modulus cannot replay an inclusion proof.
    let modulus: [u128; 18] = [1; 18];
    let a = compute_x509_issuer_id(modulus, 65537, 0, 0);
    let b = compute_x509_issuer_id(modulus, 3, 0, 0);
    assert(a != b, "Cert leaf must bind RSA exponent");
}

#[test]
fn test_compute_x509_issuer_id_changes_with_tbs_hash() {
    // P1-7: the TBS hash captures country, subject, validity, key usage,
    // etc. Changing it must move the Merkle leaf.
    let modulus: [u128; 18] = [1; 18];
    let a = compute_x509_issuer_id(modulus, 65537, 0, 0);
    let b = compute_x509_issuer_id(modulus, 65537, 1, 0);
    let c = compute_x509_issuer_id(modulus, 65537, 0, 1);
    assert(a != b, "Cert leaf must bind TBS hash hi half");
    assert(a != c, "Cert leaf must bind TBS hash lo half");
}
