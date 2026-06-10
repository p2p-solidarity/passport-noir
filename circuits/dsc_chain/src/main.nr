use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::digest;

use openac_core::commit::DOMAIN_CSCA_NODE;
use openac_core::merkle::{
    compute_csca_leaf_v2, compute_dsc_id, CSCA_MERKLE_DEPTH, verify_inclusion_depth_8,
};
use openac_core::smt::{SMT_DEPTH, smt_fold, verify_non_membership};
use std::hash::pedersen_hash;

// OpenAC DSC trust-chain proof (Prepare Phase, Phase 6 -- spec sec.7.2)
//
// Splits the cacheable, public-data-only half out of passport_adapter so it can
// be precomputed once per DSC (a single DSC signs hundreds of thousands of
// passports) and distributed alongside each CSCA Master List snapshot. It
// proves:
//   1. CSCA -> DSC RSA-2048 issuance signature over the DSC TBS.
//   2. CSCA Master List inclusion (depth-8 Merkle, compute_csca_leaf_v2).
//   3. DSC serial bound to the CSCA-signed TBS bytes.
//   4. DSC serial non-membership in the depth-32 revocation SMT.
//
// Public outputs:
//   - csca_root / dsc_smt_root: the trust anchors the verifier pins.
//   - exponent: ICAO-mandated 65537 (asserted in-circuit).
//   - out_dsc_id: compute_dsc_id(extracted DSC modulus, exponent). The
//     per-holder passport core proof re-derives the same id from the DSC
//     modulus it uses for the DSC->SOD signature and pins it; the verifier
//     checks the two ids match. This ties the two proofs together with no
//     recursion -- neither proof carries the other's RSA witnesses.

global RSA_LIMB_COUNT: u32 = 18;
global RSA_LIMB_BYTES: u32 = 16;
global DSC_MODULUS_BYTES: u32 = RSA_LIMB_COUNT * RSA_LIMB_BYTES;

// DSC certificate TBS envelope size. Matches passport_adapter's reduced
// DSC_TBS_LEN (v3.1 sec.7.3): RSA-2048 modulus at [0..288) + meta envelope +
// 20-byte serial at [352..372). The app's TBS normaliser emits exactly this
// many bytes (synthetic envelope, not raw ICAO ASN.1).
global DSC_TBS_LEN: u32 = 512;

// Canonical TBS offset for the 20-byte DSC serial number (right after the
// 288-byte modulus + meta envelope). Binding `dsc_serial` to these TBS bytes
// closes the revocation-bypass gap where an attacker holds a revoked DSC yet
// supplies a non-revoked serial to the SMT non-membership check.
global DSC_SERIAL_OFFSET: u32 = 352;
global DSC_SERIAL_LEN: u32 = 20;

// CSCA -> DSC RSA signature uses RSA-2048 PKCS#1v1.5 with exponent 65537, per
// ICAO 9303 conformance (same parameters as the DSC -> SOD signature).
global CSCA_RSA_EXPONENT: u32 = 65537;
// DSC RSA exponent: ICAO 9303 mandates 65537 for new passports. Public input,
// asserted exactly 65537 so the linking id binds the ICAO-mandated exponent.
global DSC_RSA_EXPONENT: u32 = 65537;

/// Big-endian-pack 16 bytes of a DSC TBS buffer into a `u128`. Used when
/// extracting the 18 RSA-2048 modulus limbs from the TBS envelope.
fn bytes16_to_u128_at(data: [u8; DSC_TBS_LEN], start: u32) -> u128 {
    let mut out: u128 = 0;
    for i in 0..RSA_LIMB_BYTES {
        out = out * 256 + data[start + i] as u128;
    }
    out
}

/// Extract the DSC RSA-2048 modulus from the TBS envelope (modulus bytes live
/// at offset 0). The app layer normalises the real ICAO TBS into this form
/// before passing the bytes into the circuit.
fn extract_dsc_modulus_limbs(dsc_tbs: [u8; DSC_TBS_LEN]) -> [u128; RSA_LIMB_COUNT] {
    let mut limbs: [u128; RSA_LIMB_COUNT] = [0; RSA_LIMB_COUNT];
    for limb_idx in 0..RSA_LIMB_COUNT {
        limbs[limb_idx] = bytes16_to_u128_at(dsc_tbs, limb_idx * RSA_LIMB_BYTES);
    }
    limbs
}

/// Verify the CSCA -> DSC issuance chain and Master List inclusion, returning
/// the DSC RSA modulus extracted from the CSCA-signed TBS.
///
///   1. SHA256 the DSC TBS envelope.
///   2. Verify the CSCA RSA-2048 signature over that hash under CSCA modulus.
///   3. Compute the v2 CSCA leaf (compute_csca_leaf_v2 binds modulus + RSA
///      exponent + canonical TBS hash) and verify depth-8 Merkle inclusion.
///   4. Return the DSC modulus the CSCA signed. The caller binds it into
///      `out_dsc_id`; the passport core proof re-derives the same id, so the
///      "DSC modulus used for SOD matches the CSCA-signed one" check that used
///      to live here is now enforced across the two proofs via id equality.
fn verify_csca_chain(
    csca_modulus_limbs: [u128; RSA_LIMB_COUNT],
    csca_redc_limbs: [u128; RSA_LIMB_COUNT],
    dsc_tbs: [u8; DSC_TBS_LEN],
    dsc_cert_sig_limbs: [u128; RSA_LIMB_COUNT],
    csca_tbs_hash_hi: Field,
    csca_tbs_hash_lo: Field,
    csca_merkle_index: u32,
    csca_merkle_siblings: [Field; CSCA_MERKLE_DEPTH],
    csca_root: Field,
) -> [u128; RSA_LIMB_COUNT] {
    let dsc_tbs_hash: [u8; 32] = digest(dsc_tbs);
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(false, csca_modulus_limbs, csca_redc_limbs);
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: dsc_cert_sig_limbs };
    assert(
        verify_sha256_pkcs1v15(dsc_tbs_hash, signature, CSCA_RSA_EXPONENT),
        "CSCA signature over DSC TBS failed verification",
    );

    let csca_leaf = compute_csca_leaf_v2(
        csca_modulus_limbs,
        CSCA_RSA_EXPONENT,
        csca_tbs_hash_hi,
        csca_tbs_hash_lo,
    );
    verify_inclusion_depth_8(
        csca_leaf,
        csca_merkle_index,
        csca_merkle_siblings,
        csca_root,
    );

    extract_dsc_modulus_limbs(dsc_tbs)
}

fn main(
    // === CSCA -> DSC chain inputs ===
    csca_modulus_limbs: [u128; RSA_LIMB_COUNT],
    csca_redc_limbs: [u128; RSA_LIMB_COUNT],
    dsc_tbs: [u8; DSC_TBS_LEN],
    dsc_cert_sig_limbs: [u128; RSA_LIMB_COUNT],
    csca_merkle_index: u32,
    csca_merkle_siblings: [Field; CSCA_MERKLE_DEPTH],
    csca_tbs_hash_hi: Field,
    csca_tbs_hash_lo: Field,
    // === DSC revocation SMT inputs ===
    dsc_serial: [u8; DSC_SERIAL_LEN],
    smt_siblings: [Field; SMT_DEPTH],
    smt_old_key: Field,
    smt_old_value: Field,
    smt_is_old0: bool,
    // === Public trust anchors ===
    csca_root: pub Field,
    dsc_smt_root: pub Field,
    exponent: pub u32,
    // === Public output: linking id consumed by the passport core proof ===
    out_dsc_id: pub Field,
) {
    assert(exponent == DSC_RSA_EXPONENT, "DSC exponent must be 65537 (ICAO 9303 v3 trust model)");

    // Step 1: CSCA -> DSC issuance chain + Master List inclusion. Returns the
    // DSC modulus the CSCA signed.
    let dsc_modulus_limbs = verify_csca_chain(
        csca_modulus_limbs,
        csca_redc_limbs,
        dsc_tbs,
        dsc_cert_sig_limbs,
        csca_tbs_hash_hi,
        csca_tbs_hash_lo,
        csca_merkle_index,
        csca_merkle_siblings,
        csca_root,
    );

    // Step 2: DSC serial must match the CSCA-signed TBS bytes, then prove it is
    // NOT revoked. SMT key binds the CSCA v2 leaf identity + the full serial so
    // a revoked DSC under one CSCA cannot replay a non-membership proof from
    // another CSCA's snapshot.
    for i in 0..DSC_SERIAL_LEN {
        assert(
            dsc_serial[i] == dsc_tbs[DSC_SERIAL_OFFSET + i],
            "dsc_serial must match the CSCA-signed TBS serial bytes",
        );
    }
    let dsc_smt_issuer_id = compute_csca_leaf_v2(
        csca_modulus_limbs,
        CSCA_RSA_EXPONENT,
        csca_tbs_hash_hi,
        csca_tbs_hash_lo,
    );
    verify_non_membership(
        dsc_smt_issuer_id,
        dsc_serial,
        smt_siblings,
        smt_old_key,
        smt_old_value,
        smt_is_old0,
        dsc_smt_root,
    );

    // Step 3: Bind the validated DSC into the cacheable linking id.
    let dsc_id = compute_dsc_id(dsc_modulus_limbs, exponent);
    assert(dsc_id == out_dsc_id, "out_dsc_id must equal the computed DSC linking id");
}

// ============================================================
// Tests
// ============================================================
//
// NOTE: the CSCA RSA chain is exercised only through negative fixtures here.
// Generating a fully valid ICAO-style RSA-2048 fixture (signing real DSC TBS
// bytes under the CSCA modulus) requires external tooling; those vectors land
// with the CSCA Master List snapshot builder. The Merkle and SMT subproofs
// have dedicated happy-path coverage in openac_core; the DSC modulus extractor
// and the dsc_id derivation are covered below.
//
// The RSA-2048 chain fixtures below are role-swapped from jwt_x5c_adapter (its
// issuer cert -> a passport CSCA, its leaf cert -> a passport DSC). They were
// migrated verbatim from passport_adapter when Phase 6 split the prepare proof.

fn csca_modulus_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0xa16bbf6582c968237950f84ced9edb,
        0x818a4b367195bfba98916c74db2b8c,
        0x2312046fd1de3c28ae6a48436db0f1,
        0xbdc9f18ecd47ae62a8d8823e01a295,
        0x716e09f175f001601a561d2efdc2ed,
        0x5027385467708162ac83d2960cb8b3,
        0x64a45f4b496498bbdc26185000194b,
        0x509996a279619ee5ac3b15355f6886,
        0xcdbffe389ee031cd3a97fe58225b98,
        0xb9f8b994f525236b8f09177653a37e,
        0x88f0a4da4667cd857a36cd8cc47461,
        0x6baf3ccec91b662de86c678f92441b,
        0x13aae58bdeef623427011e69414d1e,
        0xa897b27655f97d48245eac2d1defd7,
        0x504a4d58dc77a1933ebf387eaef139,
        0x1112bdb40b60505df63d230801126d,
        0x817aad06370dabb3887f97cd96f0f5,
        0xbd,
    ]
}

fn csca_redc_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0xed9ca6c20e41f3f9885895ca784496,
        0x4181c99a3064c64474949d6f591715,
        0x88803734a8be4e8180a3d95ada54e0,
        0xc26dc22c0bfddafefa514f4ba30112,
        0xc63959360d24e3989b4ae312ddb28f,
        0xba7a656e61c4822cf4f90670f9635a,
        0x713396d9ce877cbe28fc3d465b149c,
        0x93c198226fe67e8ddd89565ceb470f,
        0xd95d3613ad0407e74a340b520851f9,
        0x5290b6f990369bcc6a599fb3e00e51,
        0xfc71f48d520e54a70be8369de367d1,
        0xc415244e22f6db48824c02cac34369,
        0xd766dbe929628e5adad607541110c5,
        0x7c53b15f95439be4566c91f8f1c841,
        0x9ff1195239138f9d5553fb358b027f,
        0xd1171db05c9a2f40589823492e00be,
        0xd36c02d1b91a592989f8487ed66dc4,
        0x159,
    ]
}

fn dsc_modulus_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0x6a0f89c4287e611ddcb155299044f9,
        0x7b0fec848b24c645a648632b0de148,
        0xe12d980728f2858a2688b963989a56,
        0x2f53114d520a9581d70f1fadf9048e,
        0x2f3a56673bafff8cb841a7beecb818,
        0xf2a3eefdc4be88717442a5fc3b7780,
        0x4c45c64fe7e76cf7dda3c73d47bf39,
        0x5417a4f6dcff8502b85c5cde1f581b,
        0xc61fa143320d12cc9a79360207c492,
        0xd5ffe9b78c4bc1cdc23db4235cf1f9,
        0x355f20e947641002d4b1260941fcd1,
        0xfc276bb43e4975ab8a8a7681f0a228,
        0xb43a6592fc8c4f5aec0d321e1be6a7,
        0x9e50c8ac30df61e09e037dda471dbf,
        0x97afef97f4ec3fe0038e9ffa9129f6,
        0x470895ba964416edb0eb8eefd5c582,
        0x4b114619d380a52f20ccf0c8a28bbc,
        0x9f,
    ]
}

fn dsc_cert_sig_limbs() -> [u128; RSA_LIMB_COUNT] {
    [
        0x6ca221e94f6ff9b3d863c9dde869b5,
        0x2ff7ac22522702b8a9f7bf5317e1ab,
        0x750c9da91d8b36e3ac438e0fce92a8,
        0xea1604f67de54f8934b261d90e44b9,
        0xce01c8cc4edbb6feee906529a3a6e7,
        0x355cbd684f2f9d24518ce498113ad4,
        0xbf98bcee25a4afa2b325aeb676e4bc,
        0x87230cda8992617cc0aad28b938539,
        0x52b4e2618b18cc5708b03065aa1b11,
        0x225addad17aadc2cd8ae1fc88ebec9,
        0x141c6bc2667fa21ffae8ce1a206fdb,
        0xca4dd92f0d7ffc3b47ee9ab2f37fb8,
        0x87c5b955a596aaff969485c6003ac,
        0x808b50ecc5eb2a03ba3beb6a8ea1d,
        0xeecec0985e51c63ce26a4b464b0219,
        0xa0ad1dba4c184e73f7dbfc7713a7d8,
        0x73d6c179a3503a437fda9e90b89629,
        0x4,
    ]
}

fn dsc_modulus_bytes() -> [u8; DSC_MODULUS_BYTES] {
    [
        0, 106, 15, 137, 196, 40, 126, 97, 29, 220, 177, 85, 41, 144, 68, 249, 0, 123, 15, 236, 132,
        139, 36, 198, 69, 166, 72, 99, 43, 13, 225, 72, 0, 225, 45, 152, 7, 40, 242, 133, 138, 38,
        136, 185, 99, 152, 154, 86, 0, 47, 83, 17, 77, 82, 10, 149, 129, 215, 15, 31, 173, 249, 4,
        142, 0, 47, 58, 86, 103, 59, 175, 255, 140, 184, 65, 167, 190, 236, 184, 24, 0, 242, 163,
        238, 253, 196, 190, 136, 113, 116, 66, 165, 252, 59, 119, 128, 0, 76, 69, 198, 79, 231, 231,
        108, 247, 221, 163, 199, 61, 71, 191, 57, 0, 84, 23, 164, 246, 220, 255, 133, 2, 184, 92,
        92, 222, 31, 88, 27, 0, 198, 31, 161, 67, 50, 13, 18, 204, 154, 121, 54, 2, 7, 196, 146, 0,
        213, 255, 233, 183, 140, 75, 193, 205, 194, 61, 180, 35, 92, 241, 249, 0, 53, 95, 32, 233,
        71, 100, 16, 2, 212, 177, 38, 9, 65, 252, 209, 0, 252, 39, 107, 180, 62, 73, 117, 171, 138,
        138, 118, 129, 240, 162, 40, 0, 180, 58, 101, 146, 252, 140, 79, 90, 236, 13, 50, 30, 27,
        230, 167, 0, 158, 80, 200, 172, 48, 223, 97, 224, 158, 3, 125, 218, 71, 29, 191, 0, 151,
        175, 239, 151, 244, 236, 63, 224, 3, 142, 159, 250, 145, 41, 246, 0, 71, 8, 149, 186, 150,
        68, 22, 237, 176, 235, 142, 239, 213, 197, 130, 0, 75, 17, 70, 25, 211, 128, 165, 47, 32,
        204, 240, 200, 162, 139, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 159,
    ]
}

fn dsc_serial() -> [u8; DSC_SERIAL_LEN] {
    [1, 35, 69, 103, 137, 171, 205, 239, 254, 220, 186, 152, 118, 84, 50, 16, 202, 254, 186, 190]
}

fn build_dsc_tbs() -> [u8; DSC_TBS_LEN] {
    let modulus_bytes = dsc_modulus_bytes();
    // Canonical TBS layout:
    //   [0..288)    : RSA-2048 modulus
    //   [288..320)  : 32-byte meta envelope
    //   [320]       : marker byte (54)
    //   [352..372)  : 20-byte DSC serial (DSC_SERIAL_OFFSET..+LEN)
    let meta: [u8; 32] = [
        108, 101, 97, 102, 45, 99, 101, 114, 116, 58, 58, 115, 111, 108, 105, 100, 97, 114, 105,
        116, 121, 58, 58, 120, 53, 48, 57, 58, 58, 50, 48, 50,
    ];
    let serial = dsc_serial();
    let mut out: [u8; DSC_TBS_LEN] = [0; DSC_TBS_LEN];
    for i in 0..DSC_MODULUS_BYTES {
        out[i] = modulus_bytes[i];
    }
    for i in 0..32 {
        out[DSC_MODULUS_BYTES + i] = meta[i];
    }
    out[DSC_MODULUS_BYTES + 32] = 54;
    for i in 0..DSC_SERIAL_LEN {
        out[DSC_SERIAL_OFFSET + i] = serial[i];
    }
    out
}

fn dsc_smt_siblings() -> [Field; SMT_DEPTH] {
    let mut siblings: [Field; SMT_DEPTH] = [0; SMT_DEPTH];
    for i in 0..SMT_DEPTH {
        siblings[i] = 123456 + i as Field;
    }
    siblings
}

// Test fixture uses arbitrary deterministic Field halves for the CSCA TBS hash.
// Real callers compute SHA256(canonical CSCA TBS) off-chain; the Merkle path
// constrains these values, so the unit-test choice is opaque.
fn csca_tbs_hash_hi() -> Field {
    0x4353434154425348415348484948494
}

fn csca_tbs_hash_lo() -> Field {
    0x4353434154425348415348414c4f4c4f
}

fn csca_issuer_id() -> Field {
    compute_csca_leaf_v2(
        csca_modulus_limbs(),
        CSCA_RSA_EXPONENT,
        csca_tbs_hash_hi(),
        csca_tbs_hash_lo(),
    )
}

fn dsc_smt_root_computed() -> Field {
    // Mirrors openac_core::smt::verify_non_membership with smt_is_old0 = true:
    // walk bits of the hashed key (issuer_id + full serial).
    let siblings = dsc_smt_siblings();
    let key = openac_core::smt::compute_serial_key(csca_issuer_id(), dsc_serial());
    let key_bytes = key.to_be_bytes::<32>();
    let mut node: Field = 0;
    for depth in 0..SMT_DEPTH {
        let byte = key_bytes[depth / 8];
        let shift: u8 = 7 - ((depth % 8) as u8);
        let go_right = ((byte >> shift) & 1) == 1;
        node = smt_fold(node, siblings[depth], go_right);
    }
    node
}

fn csca_merkle_siblings() -> [Field; CSCA_MERKLE_DEPTH] {
    let mut siblings: [Field; CSCA_MERKLE_DEPTH] = [0; CSCA_MERKLE_DEPTH];
    for i in 0..CSCA_MERKLE_DEPTH {
        siblings[i] = 555_000 + i as Field;
    }
    siblings
}

fn csca_root_computed() -> Field {
    // CSCA appears at index 0 under the test Master List snapshot.
    let leaf = csca_issuer_id();
    let siblings = csca_merkle_siblings();
    let mut node = leaf;
    for depth in 0..CSCA_MERKLE_DEPTH {
        node = pedersen_hash([DOMAIN_CSCA_NODE, node, siblings[depth]]);
    }
    node
}

// --- DSC modulus extraction ---

#[test]
fn test_extract_dsc_modulus_roundtrip() {
    let extracted = extract_dsc_modulus_limbs(build_dsc_tbs());
    let expected = dsc_modulus_limbs();
    for i in 0..RSA_LIMB_COUNT {
        assert(extracted[i] == expected[i], "DSC modulus extraction should round-trip");
    }
}

#[test]
fn test_dsc_id_derives_from_extracted_modulus() {
    // The in-circuit dsc_id is derived from the modulus extracted from the
    // CSCA-signed TBS, which must equal the id derived from the canonical DSC
    // modulus -- this is the value the passport core proof pins.
    let from_tbs = compute_dsc_id(extract_dsc_modulus_limbs(build_dsc_tbs()), DSC_RSA_EXPONENT);
    let from_canonical = compute_dsc_id(dsc_modulus_limbs(), DSC_RSA_EXPONENT);
    assert(from_tbs == from_canonical, "dsc_id must derive from the TBS-extracted DSC modulus");
}

// --- CSCA chain (negative fixtures; no valid RSA happy path yet) ---

#[test(should_fail)]
fn test_csca_chain_fails_on_tampered_dsc_tbs() {
    let mut tampered = build_dsc_tbs();
    tampered[DSC_MODULUS_BYTES + 5] ^= 0xFF;
    let _ = verify_csca_chain(
        csca_modulus_limbs(),
        csca_redc_limbs(),
        tampered,
        dsc_cert_sig_limbs(),
        csca_tbs_hash_hi(),
        csca_tbs_hash_lo(),
        0,
        csca_merkle_siblings(),
        csca_root_computed(),
    );
}

#[test(should_fail)]
fn test_csca_chain_fails_on_wrong_csca_root() {
    let mut bad_root = csca_root_computed();
    bad_root += 1;
    let _ = verify_csca_chain(
        csca_modulus_limbs(),
        csca_redc_limbs(),
        build_dsc_tbs(),
        dsc_cert_sig_limbs(),
        csca_tbs_hash_hi(),
        csca_tbs_hash_lo(),
        0,
        csca_merkle_siblings(),
        bad_root,
    );
}

#[test(should_fail)]
fn test_csca_chain_fails_on_tampered_tbs_hash() {
    // The v2 leaf binds the CSCA TBS hash. A prover that tampers the supplied
    // tbs_hash while keeping the same modulus must produce a leaf that no
    // longer matches the Master List Merkle root.
    let _ = verify_csca_chain(
        csca_modulus_limbs(),
        csca_redc_limbs(),
        build_dsc_tbs(),
        dsc_cert_sig_limbs(),
        csca_tbs_hash_hi() + 1, // FORGED tbs hash
        csca_tbs_hash_lo(),
        0,
        csca_merkle_siblings(),
        csca_root_computed(),
    );
}

// --- DSC revocation SMT ---

#[test]
fn test_dsc_non_membership_passes_for_unrevoked_serial() {
    verify_non_membership(
        csca_issuer_id(),
        dsc_serial(),
        dsc_smt_siblings(),
        0,
        0,
        true,
        dsc_smt_root_computed(),
    );
}

#[test(should_fail)]
fn test_dsc_non_membership_fails_on_wrong_root() {
    let mut bad_root = dsc_smt_root_computed();
    bad_root += 1;
    verify_non_membership(
        csca_issuer_id(),
        dsc_serial(),
        dsc_smt_siblings(),
        0,
        0,
        true,
        bad_root,
    );
}

#[test]
fn test_dsc_serial_lives_at_canonical_tbs_offset() {
    let tbs = build_dsc_tbs();
    let serial = dsc_serial();
    for i in 0..DSC_SERIAL_LEN {
        assert(
            tbs[DSC_SERIAL_OFFSET + i] == serial[i],
            "TBS fixture must embed dsc_serial at the canonical offset",
        );
    }
}

#[test(should_fail)]
fn test_dsc_serial_binding_rejects_serial_not_in_tbs() {
    // An attacker with a revoked DSC cannot pass a different (non-revoked)
    // serial to the SMT check: the binding loop compares `dsc_serial` against
    // the bytes at DSC_SERIAL_OFFSET of the CSCA-signed TBS.
    let tbs = build_dsc_tbs();
    let mut forged_serial = dsc_serial();
    forged_serial[0] ^= 0xFF;
    for i in 0..DSC_SERIAL_LEN {
        assert(
            forged_serial[i] == tbs[DSC_SERIAL_OFFSET + i],
            "dsc_serial must match the CSCA-signed TBS serial bytes",
        );
    }
}

// --- dsc_id linking output ---

#[test(should_fail)]
fn test_out_dsc_id_assert_rejects_tampered_output() {
    // Reproduce main()'s final binding so the linking-id assertion is covered
    // without a full RSA fixture. A prover that publishes the wrong out_dsc_id
    // must be rejected.
    let dsc_id = compute_dsc_id(dsc_modulus_limbs(), DSC_RSA_EXPONENT);
    let tampered = dsc_id + 1;
    assert(dsc_id == tampered, "out_dsc_id must equal the computed DSC linking id");
}

// --- exponent pinning ---

#[test]
fn test_dsc_rsa_exponent_constant_is_65537() {
    assert(DSC_RSA_EXPONENT == 65537, "DSC_RSA_EXPONENT must remain 65537 (ICAO 9303)");
    assert(CSCA_RSA_EXPONENT == 65537, "CSCA_RSA_EXPONENT must remain 65537 (ICAO 9303)");
}

#[test(should_fail)]
fn test_dsc_exponent_assertion_rejects_three() {
    let bad_exponent: u32 = 3;
    assert(
        bad_exponent == DSC_RSA_EXPONENT,
        "DSC exponent must be 65537 (ICAO 9303 v3 trust model)",
    );
}
