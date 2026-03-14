use noir_rsa::rsa::verify_sha256_pkcs1v15;
use bignum::RuntimeBigNum;
use bignum::params::BigNumParams;

// Passport Signature Verifier (DSC -> SOD)
//
// Verifies that the Security Object Document (SOD) of a passport was signed
// by a valid Document Signer Certificate (DSC) using RSA-2048 + SHA-256.
//
// This is the first base proof in the OpenPassport architecture.

fn main(
    // SHA-256 hash of the signed attributes in the SOD
    sod_hash: [u8; 32],
    // RSA-2048 signature over sod_hash, from the DSC private key
    signature_limbs: [u128; 18],
    // DSC public key modulus limbs (public - verifier checks against CSCA)
    modulus_limbs: pub [u128; 18],
    // Barrett reduction parameter for the modulus
    redc_limbs: [u128; 18],
    // RSA exponent: 65537 or 3
    exponent: u32,
) {
    // Reconstruct the RSA public key parameters
    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        modulus_limbs,
        redc_limbs,
    );

    // Reconstruct the signature as a BigNum
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature_limbs };

    // Verify RSA-SHA256 PKCS#1 v1.5 signature
    assert(
        verify_sha256_pkcs1v15(sod_hash, signature, exponent),
        "Passport DSC signature verification failed",
    );
}

#[test]
fn test_rsa_sha256_verification() {
    // Generated via noir_rsa v0.10.0 signature_gen (msg: "Hello World! This is Noir-RSA")
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];

    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5,
        0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556,
        0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591,
        0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e,
        0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748,
        0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025,
        0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c,
        0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99,
        0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287,
        0xbf,
    ];

    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6,
        0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8,
        0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15,
        0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109,
        0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894,
        0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144,
        0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f,
        0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1,
        0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544,
        0x5596,
    ];

    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b,
        0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7,
        0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a,
        0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896,
        0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440,
        0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f,
        0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f,
        0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9,
        0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107,
        0x2d,
    ];

    main(hash, signature_limbs, modulus_limbs, redc_limbs, 65537);
}

// PV-2: RSA with exponent=3 (some old passports use e=3)
// RED test - no valid e=3 test vector available; documents the need for real vectors
#[test(should_fail)]
fn test_rsa_exponent_3() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    // e=3 with e=65537 test vectors should fail
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 3);
}

// PV-3: Invalid signature - tamper one limb
#[test(should_fail)]
fn test_invalid_signature_fails() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    // Tampered: first limb changed from 0xa56c... to 0xdead...
    let signature_limbs: [u128; 18] = [
        0xdeadbeefdeadbeefdeadbeefdeadbe, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 65537);
}

// PV-4: Wrong modulus (different DSC public key)
#[test(should_fail)]
fn test_wrong_modulus_fails() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    // Tampered: first limb changed
    let modulus_limbs: [u128; 18] = [
        0xdeadbeefdeadbeefdeadbeefdeadbe, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 65537);
}

// PV-5: Tampered SOD hash - flip one byte
#[test(should_fail)]
fn test_tampered_sod_hash_fails() {
    // Flipped first byte: 91 -> 92
    let hash: [u8; 32] = [
        92, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 65537);
}

// PV-6: All-zero signature
#[test(should_fail)]
fn test_zero_signature_fails() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [0; 18];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 65537);
}

// PV-7: Wrong Barrett reduction parameter
#[test(should_fail)]
fn test_wrong_redc_params_fails() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    // Tampered redc: first limb zeroed
    let redc_limbs: [u128; 18] = [
        0x0, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 65537);
}

// PV-8: Exponent = 0 (invalid)
#[test(should_fail)]
fn test_exponent_zero_fails() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 0);
}

// PV-9: Exponent = 1 (trivially insecure)
#[test(should_fail)]
fn test_exponent_one_fails() {
    let hash: [u8; 32] = [
        91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120,
        122, 131, 166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
    ];
    let modulus_limbs: [u128; 18] = [
        0x1b6191d195895b5df38941a00eace5, 0xd18c88a04b0e5a204fb4323280be55,
        0xc1d2f01fe8a294cabc5e60aeb98556, 0x813ea53b764fa89ddffd9bafa98e8,
        0xfb782a5aa5060e19b182c61a5b0591, 0x3ed0a91d93634c002dff05de91fe0,
        0x916c13e9253a809ba7d8f858f04c0e, 0x3dfc5b0b2e5c5a589dbd2a73b409c2,
        0xc326214283ec0451c712892ef7d748, 0x70d990293997e77dc8444de23edf40,
        0x565e7d47a8065923c4c651a47da025, 0x6bacd32300777b398c2dc99ab0f3f7,
        0x27f20db536146ef7710ad6ecffd56c, 0x55040a0b37f674e89df61a76efe39,
        0xb1f75729719550e7fe3df15d686a99, 0xcada91cde367961e4d82dcc08e2cf3,
        0x6ee67af8eeeb91b4fcb5cede4b6287, 0xbf,
    ];
    let redc_limbs: [u128; 18] = [
        0xe6bdbea08b7ba701fdfbd15baa73e6, 0x5a38898fe8ccb04c2de86a0042f8e,
        0x688830cdab9cc2344d0fcec773dfb8, 0x1442a296a6d89d7b533c3463b6f2b4,
        0x8ff0bc7c8116c4dbb992f317024a15, 0x90de977522adb5532c0381206711c3,
        0xa8daff3c0370775669b689d139c109, 0xd6fb4597d7cb0727aa9f234d81e328,
        0xa365752d2787c1f280230f1bbb894, 0xda474ce35717e995d256d82843b70d,
        0xf0f4824efeb77eb2f6e6b426673144, 0xae31d393ef0c42181faeed969e2e2,
        0x30e2f8f53e7cf8eb0da59ffc784a3f, 0x32a643a3002225074fc3368dc450ce,
        0x13d35a36748fa6c319609c9175d9c1, 0x49fb2cb9fa230acb1a1ac8db1b1ea9,
        0x3555949efc369e3a1eeefda224544, 0x5596,
    ];
    let signature_limbs: [u128; 18] = [
        0xa56c33662e463fa8a879805279db7b, 0x275b4fd5fcd5b1e5a24134085280a8,
        0x4e932b35cdf50f826889b035839ce7, 0x9121752d1d5f077cf4ef572a6cf184,
        0x95efa0c95a11db7880a0cd2439055a, 0xb452f4cc1f9d1e592e7f8c6fcb06e0,
        0x63716e99646d15db9fc9ba00390896, 0x7b52b8e2f99755eeef46361c239c37,
        0xcc0b9328358cc472f1e947d0d19440, 0xae2d4ee973f9e13444924f8ada5397,
        0x4045e3da340652d05ec73a4f07211f, 0xe43165ab42c48d2ee9a195bb8a9a69,
        0x6423a144562d9a1527964e0a90081f, 0x1aef35b66d4aae989a6ee1d53ccb62,
        0xb93652c7a17c0f0227852d0726c9d9, 0x8760ef7f6c6baabddac0c6d97073ee,
        0xcca3d67ca6851866ce763d1d5d8107, 0x2d,
    ];
    main(hash, signature_limbs, modulus_limbs, redc_limbs, 1);
}
