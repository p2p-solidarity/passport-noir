//! Grumpkin Pedersen primitives matching Noir stdlib bit-for-bit.
//!
//! Noir's `std::hash::pedersen_hash` / `pedersen_commitment` (1.0.0-beta.19)
//! are multi-scalar multiplications over generators derived from
//! `"DEFAULT_DOMAIN_SEPARATOR"` plus, for the hash variant, a length term
//! over the `"pedersen_hash_length"` generator:
//!
//!   commitment(input)   = Σ input_i · G_i
//!   hash(input)         = (Σ input_i · G_i  +  N · L).x
//!
//! We reuse the EXACT generator derivation the Noir compiler embeds
//! (`bn254_blackbox_solver::derive_generators`, same git rev as the noir_rs
//! toolchain) and do the curve arithmetic with ark-grumpkin.
//!
//! The revocation SMT folds call `pedersen_hash` once per inserted serial per
//! tree level (entries × 32), so the first four generators and the length
//! generator get 4-bit fixed-base window tables (~64 mixed additions per
//! scalar instead of a generic double-and-add). Higher-arity inputs
//! (csca leaf = 22, dsc_id = 20, commitment = 8) are cold paths and use plain
//! `mul_bigint`.
//!
//! Ground truth: every public function is pinned against vectors printed by
//! `nargo test` from `openac_core` (see tests at the bottom of this file).

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_grumpkin::{Affine, Projective};
use noir_rs::acir::{AcirField, FieldElement};
use std::sync::OnceLock;

const DEFAULT_DOMAIN_SEPARATOR: &[u8] = b"DEFAULT_DOMAIN_SEPARATOR";
const LENGTH_DOMAIN_SEPARATOR: &[u8] = b"pedersen_hash_length";

/// Number of leading generators with fixed-base window tables. Generators
/// 0..3 cover every hot arity (SMT fold = 3, serial key = 4).
const TABLED_GENERATORS: usize = 4;
/// 4-bit windows over the 254-bit BN254 scalar (window never straddles a
/// u64 limb because 64 % 4 == 0).
const WINDOW_BITS: usize = 4;
const WINDOWS: usize = 256 / WINDOW_BITS;
const TABLE_ENTRIES: usize = (1 << WINDOW_BITS) - 1;

struct FixedBaseTable {
    /// windows × 15 affine points: `entries[w][v-1] = v · 2^(4w) · G`.
    entries: Vec<Vec<Affine>>,
}

impl FixedBaseTable {
    fn build(base: Affine) -> Self {
        let mut entries: Vec<Vec<Projective>> = Vec::with_capacity(WINDOWS);
        let mut window_base = Projective::from(base);
        for _ in 0..WINDOWS {
            let mut row = Vec::with_capacity(TABLE_ENTRIES);
            let mut acc = window_base;
            for _ in 0..TABLE_ENTRIES {
                row.push(acc);
                acc += window_base;
            }
            entries.push(row);
            // acc is now 16 · window_base = the next window's base.
            window_base = acc;
        }
        let entries = entries
            .into_iter()
            .map(|row| Projective::normalize_batch(&row))
            .collect();
        Self { entries }
    }

    fn mul(&self, scalar: &BigInteger256) -> Projective {
        let mut acc = Projective::zero();
        for (w, row) in self.entries.iter().enumerate() {
            let bit = w * WINDOW_BITS;
            let digit = ((scalar.0[bit / 64] >> (bit % 64)) & 0xF) as usize;
            if digit != 0 {
                acc += row[digit - 1];
            }
        }
        acc
    }
}

struct PedersenContext {
    /// All commitment generators we ever need (csca leaf arity 22 is max).
    generators: Vec<Affine>,
    length_generator: Affine,
    tables: Vec<FixedBaseTable>,
    length_table: FixedBaseTable,
}

const MAX_ARITY: usize = 22;

fn context() -> &'static PedersenContext {
    static CTX: OnceLock<PedersenContext> = OnceLock::new();
    CTX.get_or_init(|| {
        let generators =
            bn254_blackbox_solver::derive_generators(DEFAULT_DOMAIN_SEPARATOR, MAX_ARITY as u32, 0);
        let length_generator =
            bn254_blackbox_solver::derive_generators(LENGTH_DOMAIN_SEPARATOR, 1, 0)[0];
        let tables = generators
            .iter()
            .take(TABLED_GENERATORS)
            .map(|g| FixedBaseTable::build(*g))
            .collect();
        let length_table = FixedBaseTable::build(length_generator);
        PedersenContext {
            generators,
            length_generator,
            tables,
            length_table,
        }
    })
}

fn scalar_repr(field: FieldElement) -> BigInteger256 {
    field.into_repr().into_bigint()
}

fn generator_mul(ctx: &PedersenContext, index: usize, field: FieldElement) -> Projective {
    if field.is_zero() {
        return Projective::zero();
    }
    let scalar = scalar_repr(field);
    if index < TABLED_GENERATORS {
        ctx.tables[index].mul(&scalar)
    } else {
        ctx.generators[index].mul_bigint(scalar)
    }
}

fn msm(inputs: &[FieldElement], length_term: Option<usize>) -> Projective {
    let ctx = context();
    assert!(
        inputs.len() <= MAX_ARITY,
        "pedersen arity {} exceeds supported maximum {MAX_ARITY}",
        inputs.len()
    );
    let mut acc = Projective::zero();
    for (i, input) in inputs.iter().enumerate() {
        acc += generator_mul(ctx, i, *input);
    }
    if let Some(len) = length_term {
        let scalar = scalar_repr(FieldElement::from(len as u128));
        acc += ctx.length_table.mul(&scalar);
        // Silence the unused-field lint path: the raw generator is kept for
        // completeness/debugging parity with the Noir stdlib derivation.
        let _ = ctx.length_generator;
    }
    acc
}

fn point_x(point: Projective) -> FieldElement {
    let affine = point.into_affine();
    match affine.xy() {
        Some((x, y)) => {
            let _ = y;
            FieldElement::from_repr(x)
        }
        None => FieldElement::zero(),
    }
}

/// Noir `std::hash::pedersen_hash(input)` (separator 0).
pub fn pedersen_hash(inputs: &[FieldElement]) -> FieldElement {
    point_x(msm(inputs, Some(inputs.len())))
}

/// Noir `std::hash::pedersen_commitment(input)` (separator 0). Returns the
/// affine (x, y) the circuits expose as `out_commitment_x/y`.
pub fn pedersen_commitment(inputs: &[FieldElement]) -> (FieldElement, FieldElement) {
    let affine = msm(inputs, None).into_affine();
    match affine.xy() {
        Some((x, y)) => (FieldElement::from_repr(x), FieldElement::from_repr(y)),
        None => (FieldElement::zero(), FieldElement::zero()),
    }
}

// ---------------------------------------------------------------------------
// openac_core mirrors (domains from circuits/openac_core/src/commit.nr).
// ---------------------------------------------------------------------------

pub const DOMAIN_PASSPORT: u128 = 0x01;
pub const DOMAIN_SMT_NODE: u128 = 0x736d7431;
pub const DOMAIN_REVOC_KEY: u128 = 0x726b6579;
pub const DOMAIN_CSCA_NODE: u128 = 0x6373636e;
pub const DOMAIN_CSCA_LEAF: u128 = 0x6373636c;
pub const DOMAIN_DSC_ID: u128 = 0x64736369;
pub const DOMAIN_PK_DIGEST: u128 = 0x706b6467;
pub const DOMAIN_LINK_TAG: u128 = 0x6c746167;
pub const SALT_SCOPE_RAND: u128 = 0x73637264;

pub fn field(value: u128) -> FieldElement {
    FieldElement::from(value)
}

/// Big-endian bytes → Field (must already be < BN254 modulus for exactness;
/// 16-byte halves always are).
pub fn field_from_be(bytes: &[u8]) -> FieldElement {
    FieldElement::from_be_bytes_reduce(bytes)
}

/// `openac_core::commit::hash_to_fields` — 32-byte hash → (hi, lo) 128-bit halves.
pub fn hash_to_fields(hash: &[u8; 32]) -> (FieldElement, FieldElement) {
    (field_from_be(&hash[..16]), field_from_be(&hash[16..]))
}

/// `openac_core::merkle::compute_csca_leaf_v2`.
pub fn compute_csca_leaf_v2(
    modulus_limbs: &[FieldElement; 18],
    rsa_exponent: u32,
    tbs_hash_hi: FieldElement,
    tbs_hash_lo: FieldElement,
) -> FieldElement {
    let mut inputs = Vec::with_capacity(22);
    inputs.push(field(DOMAIN_CSCA_LEAF));
    inputs.push(FieldElement::from(rsa_exponent as u128));
    inputs.push(tbs_hash_hi);
    inputs.push(tbs_hash_lo);
    inputs.extend_from_slice(modulus_limbs);
    pedersen_hash(&inputs)
}

/// `openac_core::merkle::compute_dsc_id`.
pub fn compute_dsc_id(modulus_limbs: &[FieldElement; 18], rsa_exponent: u32) -> FieldElement {
    let mut inputs = Vec::with_capacity(20);
    inputs.push(field(DOMAIN_DSC_ID));
    inputs.push(FieldElement::from(rsa_exponent as u128));
    inputs.extend_from_slice(modulus_limbs);
    pedersen_hash(&inputs)
}

/// CSCA Master List internal node (`pedersen_hash([DOMAIN_CSCA_NODE, l, r])`).
pub fn csca_node(left: FieldElement, right: FieldElement) -> FieldElement {
    pedersen_hash(&[field(DOMAIN_CSCA_NODE), left, right])
}

/// Revocation SMT internal node (`openac_core::smt::hash_field_pair`).
pub fn smt_node(left: FieldElement, right: FieldElement) -> FieldElement {
    pedersen_hash(&[field(DOMAIN_SMT_NODE), left, right])
}

/// `openac_core::smt::compute_serial_key` — issuer-bound 20-byte serial key.
pub fn compute_serial_key(issuer_id: FieldElement, serial: &[u8; 20]) -> FieldElement {
    let hi = field_from_be(&serial[..16]);
    let lo = field_from_be(&serial[16..]);
    pedersen_hash(&[field(DOMAIN_REVOC_KEY), issuer_id, hi, lo])
}

/// `openac_core::device::pk_digest_from_bytes`.
pub fn pk_digest_from_bytes(pk_x: &[u8; 32], pk_y: &[u8; 32]) -> FieldElement {
    let (x_hi, x_lo) = hash_to_fields(pk_x);
    let (y_hi, y_lo) = hash_to_fields(pk_y);
    pedersen_hash(&[field(DOMAIN_PK_DIGEST), x_hi, x_lo, y_hi, y_lo])
}

/// `openac_core::profile::derive_scoped_link_rand`.
pub fn derive_scoped_link_rand(seed: FieldElement, scope: FieldElement) -> FieldElement {
    pedersen_hash(&[field(SALT_SCOPE_RAND), seed, scope])
}

/// `openac_core::show::compute_link_tag`.
pub fn compute_link_tag(
    credential_type: FieldElement,
    link_rand: FieldElement,
    link_scope: FieldElement,
    epoch: FieldElement,
) -> FieldElement {
    pedersen_hash(&[
        field(DOMAIN_LINK_TAG),
        credential_type,
        link_rand,
        link_scope,
        epoch,
    ])
}

/// `openac_core::commit::commit_passport_v3_1` (arity-8 Grumpkin commitment).
#[allow(clippy::too_many_arguments)]
pub fn commit_passport_v3_1(
    claims: FieldElement,
    sod_hash_hi: FieldElement,
    sod_hash_lo: FieldElement,
    dg1_hash_hi: FieldElement,
    dg1_hash_lo: FieldElement,
    pk_digest: FieldElement,
    link_rand: FieldElement,
) -> (FieldElement, FieldElement) {
    pedersen_commitment(&[
        field(DOMAIN_PASSPORT),
        claims,
        sod_hash_hi,
        sod_hash_lo,
        dg1_hash_hi,
        dg1_hash_lo,
        pk_digest,
        link_rand,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every expected value below was printed by Noir itself:
    //   circuits/openac_core tmp_print_vectors via
    //   `nargo test --package openac_core tmp_print_vectors --show-output`
    // (nargo 1.0.0-beta.19, the toolchain that compiled the shipped circuits).

    fn hex(field: FieldElement) -> String {
        format!("0x{}", field.to_hex())
    }

    fn limbs_fixture() -> [FieldElement; 18] {
        core::array::from_fn(|i| FieldElement::from(0x1000_0000_0000_0000u128 + i as u128))
    }

    #[test]
    fn pedersen_hash_matches_noir_stdlib() {
        let h = pedersen_hash(&[field(1), field(2), field(3)]);
        assert_eq!(
            hex(h),
            "0x0c21b8e26f60b476d9568df4807131ff70d8b7fffb03fa07960aa1cac9be7c46"
        );
    }

    #[test]
    fn pedersen_commitment_matches_noir_stdlib() {
        let (x, y) = pedersen_commitment(&[field(5), field(6)]);
        assert_eq!(
            hex(x),
            "0x0903a1dd1cae0f578d0c077f153d46fd3af192364675a36a7d3b19ae7add3028"
        );
        assert_eq!(
            hex(y),
            "0x2bb136034f82ce52e12d8d89adc146403075b33cb19a061b77132a92c39f5712"
        );
    }

    #[test]
    fn dsc_id_matches_openac_core() {
        let id = compute_dsc_id(&limbs_fixture(), 65537);
        assert_eq!(
            hex(id),
            "0x2cbe73f8c5cb81afebead1b5af87bf6713219984d80d8bfb35d29777ea5419c0"
        );
    }

    #[test]
    fn csca_leaf_v2_matches_openac_core() {
        let leaf = compute_csca_leaf_v2(&limbs_fixture(), 65537, field(0x1111), field(0x2222));
        assert_eq!(
            hex(leaf),
            "0x1c394b507e67795f70e6e62db99fd7ed34babf137ca9371e64085d4ff5bb1fb6"
        );
    }

    #[test]
    fn smt_fold_matches_openac_core() {
        let node = smt_node(field(7), field(9));
        assert_eq!(
            hex(node),
            "0x1601a61be778b451a007d6b729f59f4f545fa1ce6c1513e38ef4fa4362c3bbad"
        );
    }

    #[test]
    fn serial_key_matches_openac_core() {
        let serial: [u8; 20] = [
            1, 35, 69, 103, 137, 171, 205, 239, 254, 220, 186, 152, 118, 84, 50, 16, 202, 254, 186,
            190,
        ];
        let key = compute_serial_key(field(11), &serial);
        assert_eq!(
            hex(key),
            "0x208d3db53813e51adbe5f525a4aee4f6bedeeab48e030d3b88a8fe44f89fc017"
        );
    }

    #[test]
    fn pk_digest_matches_openac_core() {
        let digest = pk_digest_from_bytes(&[0xAA; 32], &[0xBB; 32]);
        assert_eq!(
            hex(digest),
            "0x09e0b324ae32fe333e764c01f82f9fc433aefb7e13251f34098359949213aee1"
        );
    }

    #[test]
    fn scoped_link_rand_matches_openac_core() {
        let rand = derive_scoped_link_rand(field(12345), field(99));
        assert_eq!(
            hex(rand),
            "0x0ff9badb00a33872ee8a68b2e70c320e252443b3424c4407395a6c06e15f3f5d"
        );
    }

    #[test]
    fn link_tag_matches_openac_core() {
        let tag = compute_link_tag(field(1), field(10), field(30), field(40));
        assert_eq!(
            hex(tag),
            "0x11585ee5c022531fa8d45623734ee4abcda4c02d2f6ed70d3924852ec8e9f9e7"
        );
    }

    #[test]
    fn commit_passport_v3_1_matches_openac_core() {
        let (x, y) = commit_passport_v3_1(
            field(9),
            field(1),
            field(2),
            field(3),
            field(4),
            field(7777),
            field(42),
        );
        assert_eq!(
            hex(x),
            "0x1816e697d65431f63a084f128b8a712fc1765636e8361ce3d21c737ef9094238"
        );
        assert_eq!(
            hex(y),
            "0x193665a353d418be6f4b266cd666db9783e1b9f1236f349cc2977c9939a8b6b7"
        );
    }
}
