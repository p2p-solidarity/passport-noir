use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::digest;

use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_X509};
use openac_core::device::pk_digest_from_bytes;
use openac_core::profile::{derive_x509_link_rand, MAX_DOMAIN_LEN, pack_x509_domain};
use openac_core::smt::{smt_fold, SMT_DEPTH, verify_non_membership};
use std::embedded_curve_ops::EmbeddedCurvePoint;

global CERT_TBS_LEN: u32 = 1536;
// Shrunk from 4096 in v3.1: Google OIDC id_token payloads are <1KB; university
// SD-JWT payloads live in sdjwt_adapter, not here. App must zero-pad the
// base64url-decoded payload to exactly this length before prove.
global JWT_PAYLOAD_LEN: u32 = 1024;
global LIMB_COUNT: u32 = 18;
global LIMB_BYTES: u32 = 16;
global LEAF_MODULUS_BYTES: u32 = LIMB_COUNT * LIMB_BYTES;
global RSA_EXPONENT: u32 = 65537;

// Issuer format tags for the fixed-offset claim extractor (spec/x509-issues.md P0-G).
// Each tag corresponds to an app-layer canonical payload layout; the app
// normalises the raw JWT payload into this form before proving so the byte
// offset of the email_domain claim is stable. Adding a new issuer is a
// three-step change: (1) append a new tag constant here, (2) append its offset
// constant, (3) extend the `extract_claim_by_tag` dispatch branch.
global ISSUER_FORMAT_GOOGLE_OIDC_V1: Field = 1;
global ISSUER_FORMAT_APPLE_ID_V1: Field = 2;
global ISSUER_FORMAT_MICROSOFT_ENTRA_V1: Field = 3;

// Canonical byte offsets of the email_domain / upn claim value within each
// normalised payload layout. Derived from the app-layer JSON template; if the
// app team adjusts the canonical form, update these constants in lock-step.
//
//   - Google OIDC v1   layout: `{"email_domain":"..."` -> offset 17
//   - Apple ID   v1   layout: `{"apple_email":"..."`  -> offset 16
//   - MS Entra   v1   layout: `{"upn_domain":"..."`   -> offset 15
global GOOGLE_OIDC_V1_EMAIL_DOMAIN_OFFSET: u32 = 17;
global APPLE_ID_V1_EMAIL_DOMAIN_OFFSET: u32 = 16;
global MICROSOFT_ENTRA_V1_EMAIL_DOMAIN_OFFSET: u32 = 15;

fn build_runtime_signature(
    signature_limbs: [u128; LIMB_COUNT],
    modulus_limbs: [u128; LIMB_COUNT],
    redc_limbs: [u128; LIMB_COUNT],
) -> RuntimeBigNum<18, 2048> {
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, redc_limbs);
    RuntimeBigNum { params, limbs: signature_limbs }
}

fn bytes16_to_u128_at(data: [u8; CERT_TBS_LEN], start: u32) -> u128 {
    let mut out: u128 = 0;
    for i in 0..LIMB_BYTES {
        out = out * 256 + data[start + i] as u128;
    }
    out
}

fn extract_leaf_modulus_limbs(leaf_tbs: [u8; CERT_TBS_LEN]) -> [u128; LIMB_COUNT] {
    let mut limbs: [u128; LIMB_COUNT] = [0; LIMB_COUNT];
    for limb_idx in 0..LIMB_COUNT {
        limbs[limb_idx] = bytes16_to_u128_at(leaf_tbs, limb_idx * LIMB_BYTES);
    }
    limbs
}

// SMT primitives moved to `openac_core::smt` in v3.1 so that `passport_adapter`
// (DSC revocation) can share the same implementation. Import above.

/// v3.1 replaces the v3.0 marker-search loop with a fixed-offset dispatch keyed
/// by `issuer_format_tag`. See `spec/x509-issues.md P0-G` and
/// `spec/x509-circuits.md sec. 4`. The app layer canonicalizes the JWT payload to a
/// known per-issuer field order before passing into the circuit, so the claim
/// byte offset is stable and no scanning is required. Savings: ~10k ACIR opcodes
/// versus the full-payload marker scan.
fn extract_claim_by_tag(
    payload: [u8; JWT_PAYLOAD_LEN],
    issuer_format_tag: Field,
) -> ([u8; MAX_DOMAIN_LEN], u8) {
    let is_google = issuer_format_tag == ISSUER_FORMAT_GOOGLE_OIDC_V1;
    let is_apple = issuer_format_tag == ISSUER_FORMAT_APPLE_ID_V1;
    let is_microsoft = issuer_format_tag == ISSUER_FORMAT_MICROSOFT_ENTRA_V1;
    assert(
        is_google | is_apple | is_microsoft,
        "Unsupported issuer_format_tag (accepted: 1=GoogleOIDCv1, 2=AppleIDv1, 3=MicrosoftEntraV1)",
    );

    let offset = if is_google {
        GOOGLE_OIDC_V1_EMAIL_DOMAIN_OFFSET
    } else if is_apple {
        APPLE_ID_V1_EMAIL_DOMAIN_OFFSET
    } else {
        MICROSOFT_ENTRA_V1_EMAIL_DOMAIN_OFFSET
    };

    let mut domain: [u8; MAX_DOMAIN_LEN] = [0; MAX_DOMAIN_LEN];
    let mut length: u8 = 0;
    let mut closed = false;

    for i in 0..MAX_DOMAIN_LEN {
        let value = payload[offset + i];
        if !closed & (value != 34) & (value != 0) {
            domain[i] = value;
            length += 1;
        } else {
            closed = true;
        }
    }

    assert(length > 0, "Normalized JWT domain missing value");
    (domain, length)
}

fn main(
    leaf_tbs: [u8; CERT_TBS_LEN],
    issuer_tbs: [u8; CERT_TBS_LEN],
    leaf_sig: [u128; LIMB_COUNT],
    issuer_sig: [u128; LIMB_COUNT],
    serial_number: [u8; 20],
    smt_siblings: [Field; SMT_DEPTH],
    smt_old_key: Field,
    smt_old_value: Field,
    smt_is_old0: bool,
    jwt_payload_norm: [u8; JWT_PAYLOAD_LEN],
    jwt_sig: [u128; LIMB_COUNT],
    jwt_modulus_limbs: [u128; LIMB_COUNT],
    jwt_redc_limbs: [u128; LIMB_COUNT],
    issuer_redc_limbs: [u128; LIMB_COUNT],
    link_rand_p: Field,
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
    jwt_payload_b64h: pub [u8; 32],
    jwt_signed_hash: pub [u8; 32],
    issuer_modulus: pub [u128; LIMB_COUNT],
    smt_root: pub Field,
    issuer_format_tag: pub Field,
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    let leaf_tbs_hash: [u8; 32] = digest(leaf_tbs);
    let issuer_tbs_hash: [u8; 32] = digest(issuer_tbs);

    let leaf_signature = build_runtime_signature(leaf_sig, issuer_modulus, issuer_redc_limbs);
    assert(
        verify_sha256_pkcs1v15(leaf_tbs_hash, leaf_signature, RSA_EXPONENT),
        "Leaf certificate signature verification failed",
    );

    let issuer_signature = build_runtime_signature(issuer_sig, issuer_modulus, issuer_redc_limbs);
    assert(
        verify_sha256_pkcs1v15(issuer_tbs_hash, issuer_signature, RSA_EXPONENT),
        "Issuer certificate signature verification failed",
    );

    let extracted_modulus = extract_leaf_modulus_limbs(leaf_tbs);
    for i in 0..LIMB_COUNT {
        assert(extracted_modulus[i] == jwt_modulus_limbs[i], "Leaf cert JWT modulus mismatch");
    }

    verify_non_membership(
        serial_number,
        smt_siblings,
        smt_old_key,
        smt_old_value,
        smt_is_old0,
        smt_root,
    );

    let payload_hash: [u8; 32] = digest(jwt_payload_norm);
    for i in 0..32 {
        assert(payload_hash[i] == jwt_payload_b64h[i], "JWT payload hash mismatch");
    }

    let jwt_signature = build_runtime_signature(jwt_sig, jwt_modulus_limbs, jwt_redc_limbs);
    assert(
        verify_sha256_pkcs1v15(jwt_signed_hash, jwt_signature, RSA_EXPONENT),
        "JWT signature verification failed",
    );

    let commitment = compute_jwt_x5c_commitment(
        jwt_payload_norm,
        issuer_format_tag,
        link_rand_p,
        enclave_pk_x,
        enclave_pk_y,
    );
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);
}

/// Path A v3 commitment derivation shared with the in-circuit `main` path.
/// Extracted so that unit tests can exercise the Pedersen binding without
/// generating a valid RSA-2048 fixture for every run.
fn compute_jwt_x5c_commitment(
    jwt_payload_norm: [u8; JWT_PAYLOAD_LEN],
    issuer_format_tag: Field,
    link_rand_p: Field,
    enclave_pk_x: [u8; 32],
    enclave_pk_y: [u8; 32],
) -> EmbeddedCurvePoint {
    let (domain_bytes, domain_len) = extract_claim_by_tag(jwt_payload_norm, issuer_format_tag);
    let (attr_hi, attr_lo) = pack_x509_domain(domain_bytes, domain_len);
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let pk_digest = pk_digest_from_bytes(enclave_pk_x, enclave_pk_y);
    commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x)
}

// ============================================================
// Tests
// ============================================================

fn issuer_modulus_limbs() -> [u128; LIMB_COUNT] {
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

fn issuer_redc_limbs() -> [u128; LIMB_COUNT] {
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

fn leaf_modulus_limbs() -> [u128; LIMB_COUNT] {
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

fn leaf_redc_limbs() -> [u128; LIMB_COUNT] {
    [
        0x95d02bcbe5120b3fc6a2d510fa13fb,
        0x350e98c31b8312ca650c495c0b0153,
        0x7ef6569091104f09c07c03032de86,
        0x3c0299b4c453276e0f5c19615e86c3,
        0x8aed3af6b523fe2791a3847151ef45,
        0xd461358768bc7e5299cc231bfbca87,
        0x80ef882af94934877bc98368895a98,
        0x69120869b6115eec40ad8eea7b10b2,
        0x714f5b3e8533562255939f19a3837b,
        0x22507d6c66c06758bdb2071f3de1d5,
        0x8480ba04b657e969caad7ad604d80a,
        0x65ab7ea0a01baf2e060aeb66c83c74,
        0x39161092d7d44af2ef85e228840a2d,
        0xd7b807e70cef048eb365899137a828,
        0x9b8faaec010d524e3aacdc98c6e58,
        0x719880e9d6e0ca9c6d8199d6afda54,
        0x6ad7a5f20fb6110e212c86dcf35391,
        0x19b,
    ]
}

fn leaf_sig_limbs() -> [u128; LIMB_COUNT] {
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

fn issuer_sig_limbs() -> [u128; LIMB_COUNT] {
    [
        0xbaf526f1476c3b7e603abee9d8d294,
        0xb45a12564ba041ab8225d2d289efd,
        0xa19e0a704b89f69c0fb45d5115c3c8,
        0x94055f55bd17a61c477a3977767e3d,
        0xdcbf0b3cbfad7ed4371220041ac0d9,
        0x6ce1606e9c35611b4dd4a7f1d581a1,
        0xc6a21d46941835cbd33a32efe4a94c,
        0x8963a0d5ebb37eb219274198ac0e1c,
        0x65e92a30a27579bdea7ad3aac7ff68,
        0xb0323da827789c0ea3cccb4b2591e1,
        0xdc85c311ab0c78111820c8c4d4d2b8,
        0x7322514eb9d1e18b2575cada540d7c,
        0xe04f74bc53139d02d624e4077ffce7,
        0x8dd7fc613e117179b6607fb679e162,
        0x9ea351abec002a77285f228021895,
        0x4f16a3c3880c5fb3dbec743c6428b7,
        0x8e6d0ccdc88a67ae0f213abc27684c,
        0xaf,
    ]
}

fn jwt_sig_limbs() -> [u128; LIMB_COUNT] {
    [
        0xd8b46cdfcb6b3ae0dc4c1316fbc76a,
        0x980266be95574d5685a96825e2cf72,
        0xd2710caceda86d0b9860247ab2bfb7,
        0x3462334ee835aa0392b4c29e4f3c53,
        0xd25f67564cc2aeee8a170757f275f,
        0xc1501cf4e7fba21115bd76e2b11d07,
        0x18ddc0e228e1f248d1745e712a9769,
        0x6f74b5050758cd129d1ff7fd2fb30b,
        0xd7a5530cc6f5b0c201199b540bc2cb,
        0xf67dc8d10f1e32acb4479500229fc6,
        0x4fd2d05001b390122f57ce0a441dac,
        0x3396cfebdf0f57c5469314422e8e27,
        0x320fb29a703bfde21d1fa1fa4e9ef5,
        0xfc5f688bc0e0a2f5dbfec48ac9f8d1,
        0xc8d0311814bca03a6eadd7f1c67679,
        0xc4ae29a19a59c8cbadb33f523a1141,
        0xfbc0bc843bd2de91e249cb384bfac5,
        0x1c,
    ]
}

fn leaf_modulus_bytes() -> [u8; LEAF_MODULUS_BYTES] {
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

fn build_leaf_tbs() -> [u8; CERT_TBS_LEN] {
    let modulus_bytes = leaf_modulus_bytes();
    let meta: [u8; 32] = [
        108, 101, 97, 102, 45, 99, 101, 114, 116, 58, 58, 115, 111, 108, 105, 100, 97, 114, 105,
        116, 121, 58, 58, 120, 53, 48, 57, 58, 58, 50, 48, 50,
    ];

    let mut out: [u8; CERT_TBS_LEN] = [0; CERT_TBS_LEN];
    for i in 0..LEAF_MODULUS_BYTES {
        out[i] = modulus_bytes[i];
    }
    for i in 0..32 {
        out[LEAF_MODULUS_BYTES + i] = meta[i];
    }
    out[LEAF_MODULUS_BYTES + 32] = 54;
    out
}

fn build_issuer_tbs() -> [u8; CERT_TBS_LEN] {
    let meta: [u8; 34] = [
        105, 115, 115, 117, 101, 114, 45, 99, 101, 114, 116, 58, 58, 115, 111, 108, 105, 100, 97,
        114, 105, 116, 121, 58, 58, 114, 111, 111, 116, 58, 58, 50, 48, 50,
    ];
    let mut out: [u8; CERT_TBS_LEN] = [0; CERT_TBS_LEN];
    for i in 0..34 {
        out[i] = meta[i];
    }
    out[34] = 54;
    out
}

fn build_payload() -> [u8; JWT_PAYLOAD_LEN] {
    let text: [u8; 67] = [
        123, 34, 101, 109, 97, 105, 108, 95, 100, 111, 109, 97, 105, 110, 34, 58, 34, 99, 115, 105,
        101, 46, 110, 116, 117, 46, 101, 100, 117, 46, 116, 119, 34, 44, 34, 105, 115, 115, 34, 58,
        34, 115, 111, 108, 105, 100, 97, 114, 105, 116, 121, 34, 44, 34, 115, 117, 98, 34, 58, 34,
        97, 108, 105, 99, 101, 34, 125,
    ];
    let mut out: [u8; JWT_PAYLOAD_LEN] = [0; JWT_PAYLOAD_LEN];
    for i in 0..67 {
        out[i] = text[i];
    }
    out
}

/// Apple ID v1 canonical payload: `{"apple_email":"apple.example"}`. The value
/// starts at offset 16 (after the 16-byte `{"apple_email":"` prefix).
fn build_apple_payload() -> [u8; JWT_PAYLOAD_LEN] {
    // { " a p p l e _ e m a i l " : " a p p l e . e x a m p l e " }
    let text: [u8; 31] = [
        123, 34, 97, 112, 112, 108, 101, 95, 101, 109, 97, 105, 108, 34, 58, 34, 97, 112, 112, 108,
        101, 46, 101, 120, 97, 109, 112, 108, 101, 34, 125,
    ];
    let mut out: [u8; JWT_PAYLOAD_LEN] = [0; JWT_PAYLOAD_LEN];
    for i in 0..31 {
        out[i] = text[i];
    }
    out
}

/// Microsoft Entra v1 canonical payload: `{"upn_domain":"microsoft.com"}`. The
/// value starts at offset 15 (after the 15-byte `{"upn_domain":"` prefix).
fn build_microsoft_payload() -> [u8; JWT_PAYLOAD_LEN] {
    // { " u p n _ d o m a i n " : " m i c r o s o f t . c o m " }
    let text: [u8; 30] = [
        123, 34, 117, 112, 110, 95, 100, 111, 109, 97, 105, 110, 34, 58, 34, 109, 105, 99, 114, 111,
        115, 111, 102, 116, 46, 99, 111, 109, 34, 125,
    ];
    let mut out: [u8; JWT_PAYLOAD_LEN] = [0; JWT_PAYLOAD_LEN];
    for i in 0..30 {
        out[i] = text[i];
    }
    out
}

fn jwt_signed_hash() -> [u8; 32] {
    [
        171, 249, 242, 56, 8, 23, 222, 134, 192, 138, 52, 138, 58, 234, 101, 61, 204, 9, 99, 12,
        197, 194, 32, 70, 164, 29, 233, 127, 223, 219, 82, 62,
    ]
}

/// Dynamically derive the payload hash fixture so it automatically tracks any
/// change to `JWT_PAYLOAD_LEN` or `build_payload()` contents. Previous versions
/// hardcoded the SHA256 of a 4096-byte zero-padded buffer, which would silently
/// desync after the v3.1 payload shrink.
fn jwt_payload_hash() -> [u8; 32] {
    digest(build_payload())
}

fn serial_number() -> [u8; 20] {
    [1, 35, 69, 103, 137, 171, 205, 239, 254, 220, 186, 152, 118, 84, 50, 16, 202, 254, 186, 190]
}

fn smt_siblings() -> [Field; SMT_DEPTH] {
    let mut siblings: [Field; SMT_DEPTH] = [0; SMT_DEPTH];
    for i in 0..SMT_DEPTH {
        siblings[i] = 123456 + i as Field;
    }
    siblings
}

/// Compute the SMT root that the revocation witness `verify_serial_non_membership`
/// actually produces for the test fixture (`smt_is_old0 = true`, `smt_siblings[i]
/// = 123456 + i`). Computing on the fly avoids a hardcoded constant that would
/// (a) drift if the logic changes and (b) potentially exceed the bn254 field
/// modulus when written as a literal.
fn smt_root() -> Field {
    let siblings = smt_siblings();
    let serial = serial_number();
    let mut node: Field = 0;
    for depth in 0..SMT_DEPTH {
        let byte = serial[depth / 8];
        let shift: u8 = 7 - ((depth % 8) as u8);
        let go_right = ((byte >> shift) & 1) == 1;
        node = smt_fold(node, siblings[depth], go_right);
    }
    node
}

// Canonical P-256 test public key, shared with circuits/device_binding.
// Using the same fixture keeps Path A pk_digest test vectors consistent
// across prepare adapters and the standalone device_binding circuit.
fn test_enclave_pk_x() -> [u8; 32] {
    [
        0x43, 0xa3, 0x93, 0x7c, 0xff, 0x2b, 0xcb, 0x51, 0xd0, 0x93, 0xf0, 0x01, 0x7c, 0x32, 0x99,
        0xef, 0x5f, 0xec, 0x7c, 0x97, 0x16, 0xd5, 0xb9, 0xc6, 0x76, 0xfd, 0xaf, 0x78, 0xc2, 0x0b,
        0x0f, 0x78,
    ]
}

fn test_enclave_pk_y() -> [u8; 32] {
    [
        0x4f, 0x95, 0x5f, 0x33, 0xc0, 0x93, 0x45, 0x2f, 0x18, 0xcd, 0xb7, 0x68, 0x54, 0xef, 0x29,
        0x11, 0xe3, 0x7c, 0x51, 0xc9, 0x5c, 0x78, 0x1a, 0x00, 0xb6, 0xa8, 0xfb, 0x51, 0x5b, 0x4e,
        0xeb, 0x4a,
    ]
}

#[test]
fn test_extract_leaf_modulus_roundtrip() {
    let extracted = extract_leaf_modulus_limbs(build_leaf_tbs());
    let expected = leaf_modulus_limbs();
    for i in 0..LIMB_COUNT {
        assert(extracted[i] == expected[i], "Leaf modulus extraction should round-trip");
    }
}

#[test]
fn test_extract_claim_by_tag_from_payload() {
    let (domain, len) = extract_claim_by_tag(build_payload(), ISSUER_FORMAT_GOOGLE_OIDC_V1);
    assert(len == 15, "email_domain should be extracted from the normalized payload");
    assert(domain[0] == 99, "Domain extraction should keep leading bytes");
    assert(domain[14] == 119, "Domain extraction should keep trailing bytes");
}

#[test]
fn test_extract_claim_by_tag_apple_id() {
    let (domain, len) = extract_claim_by_tag(build_apple_payload(), ISSUER_FORMAT_APPLE_ID_V1);
    assert(len == 13, "apple_email value 'apple.example' should extract (13 chars)");
    assert(domain[0] == 97, "Apple payload first byte should be 'a'");
    assert(domain[12] == 101, "Apple payload last byte should be 'e'");
}

#[test]
fn test_extract_claim_by_tag_microsoft_entra() {
    let (domain, len) =
        extract_claim_by_tag(build_microsoft_payload(), ISSUER_FORMAT_MICROSOFT_ENTRA_V1);
    assert(len == 13, "upn_domain value 'microsoft.com' should extract (13 chars)");
    assert(domain[0] == 109, "MS payload first byte should be 'm'");
    assert(domain[12] == 109, "MS payload last byte should be 'm'");
}

#[test(should_fail)]
fn test_extract_claim_by_tag_rejects_unknown_issuer() {
    // v3.1 accepts tag in {1, 2, 3}. Anything else must fail-closed; do not
    // silently fall back to any known issuer's offset.
    let _ = extract_claim_by_tag(build_payload(), 999);
}

#[test]
fn test_jwt_x5c_commitment_matches_manual_derivation() {
    // Happy path: helper output must equal the manual v3 commitment
    // (DOMAIN_X509 || attr_hi || attr_lo || pk_digest || link_rand_x).
    // This exercises the full commitment derivation (email-domain extraction,
    // x509 packing, link_rand derivation, pk_digest, commit_attributes_v3)
    // without depending on a valid RSA-2048 fixture for the cert / JWT chain.
    let payload = build_payload();
    let (domain, domain_len) = extract_claim_by_tag(payload, ISSUER_FORMAT_GOOGLE_OIDC_V1);
    let (attr_hi, attr_lo) = pack_x509_domain(domain, domain_len);
    let link_rand_p: Field = 424242;
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let expected = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);

    let actual = compute_jwt_x5c_commitment(
        payload,
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        link_rand_p,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
    );
    assert(actual.x == expected.x, "v3 commitment X must match manual recomputation");
    assert(actual.y == expected.y, "v3 commitment Y must match manual recomputation");
}

#[test]
fn test_jwt_x5c_commitment_binds_enclave_pk() {
    // Path A guarantee: swapping the enclave public key must change the commitment,
    // even when every other input (payload, link_rand_p) stays constant.
    let payload = build_payload();
    let link_rand_p: Field = 424242;
    let c_a = compute_jwt_x5c_commitment(
        payload,
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        link_rand_p,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
    );

    let mut tampered_x = test_enclave_pk_x();
    tampered_x[0] ^= 0xFF;
    let c_b = compute_jwt_x5c_commitment(
        payload,
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        link_rand_p,
        tampered_x,
        test_enclave_pk_y(),
    );

    assert(c_a.x != c_b.x, "Different enclave pk_x must yield a different v3 commitment");
}

#[test]
fn test_jwt_x5c_commitment_binds_link_rand() {
    // Rerandomisation check: changing only link_rand_p must change the commitment.
    let payload = build_payload();
    let c_a = compute_jwt_x5c_commitment(
        payload,
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        424242,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
    );
    let c_b = compute_jwt_x5c_commitment(
        payload,
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        424243,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
    );
    assert(c_a.x != c_b.x, "Different link_rand_p must yield a different v3 commitment");
}

#[test(should_fail)]
fn test_jwt_x5c_adapter_rejects_wrong_payload_hash() {
    let payload = build_payload();
    let (domain, domain_len) = extract_claim_by_tag(payload, ISSUER_FORMAT_GOOGLE_OIDC_V1);
    let (attr_hi, attr_lo) = pack_x509_domain(domain, domain_len);
    let link_rand_p: Field = 424242;
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let commitment = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    let mut wrong_payload_hash = jwt_payload_hash();
    wrong_payload_hash[0] ^= 0xFF;

    main(
        build_leaf_tbs(),
        build_issuer_tbs(),
        leaf_sig_limbs(),
        issuer_sig_limbs(),
        serial_number(),
        smt_siblings(),
        0,
        0,
        true,
        payload,
        jwt_sig_limbs(),
        leaf_modulus_limbs(),
        leaf_redc_limbs(),
        issuer_redc_limbs(),
        link_rand_p,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        wrong_payload_hash,
        jwt_signed_hash(),
        issuer_modulus_limbs(),
        smt_root(),
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        commitment.x,
        commitment.y,
    );
}

#[test(should_fail)]
fn test_jwt_x5c_adapter_rejects_wrong_enclave_pk() {
    // Path A: commitment binds pk_digest. Supplying a different enclave key
    // than the one committed must produce a commitment mismatch.
    let payload = build_payload();
    let (domain, domain_len) = extract_claim_by_tag(payload, ISSUER_FORMAT_GOOGLE_OIDC_V1);
    let (attr_hi, attr_lo) = pack_x509_domain(domain, domain_len);
    let link_rand_p: Field = 424242;
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let commitment = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);

    let mut tampered_pk_x = test_enclave_pk_x();
    tampered_pk_x[0] ^= 0xFF;

    main(
        build_leaf_tbs(),
        build_issuer_tbs(),
        leaf_sig_limbs(),
        issuer_sig_limbs(),
        serial_number(),
        smt_siblings(),
        0,
        0,
        true,
        payload,
        jwt_sig_limbs(),
        leaf_modulus_limbs(),
        leaf_redc_limbs(),
        issuer_redc_limbs(),
        link_rand_p,
        tampered_pk_x,
        test_enclave_pk_y(),
        jwt_payload_hash(),
        jwt_signed_hash(),
        issuer_modulus_limbs(),
        smt_root(),
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        commitment.x,
        commitment.y,
    );
}

#[test(should_fail)]
fn test_jwt_x5c_adapter_rejects_wrong_commitment() {
    let payload = build_payload();
    let (domain, domain_len) = extract_claim_by_tag(payload, ISSUER_FORMAT_GOOGLE_OIDC_V1);
    let (attr_hi, attr_lo) = pack_x509_domain(domain, domain_len);
    let link_rand_p: Field = 424242;
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let commitment = commit_attributes_v3(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);

    main(
        build_leaf_tbs(),
        build_issuer_tbs(),
        leaf_sig_limbs(),
        issuer_sig_limbs(),
        serial_number(),
        smt_siblings(),
        0,
        0,
        true,
        payload,
        jwt_sig_limbs(),
        leaf_modulus_limbs(),
        leaf_redc_limbs(),
        issuer_redc_limbs(),
        link_rand_p,
        test_enclave_pk_x(),
        test_enclave_pk_y(),
        jwt_payload_hash(),
        jwt_signed_hash(),
        issuer_modulus_limbs(),
        smt_root(),
        ISSUER_FORMAT_GOOGLE_OIDC_V1,
        commitment.x + 1,
        commitment.y,
    );
}
