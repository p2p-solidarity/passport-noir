use sha256::digest;

global HASH_BYTES: u32 = 32;
global PREPARE_DOMAIN_BYTES: u32 = 16;
global SHOW_DOMAIN_BYTES: u32 = 14;
global SCOPE_DOMAIN_BYTES: u32 = 15;
global EPOCH_BYTES: u32 = 4;

fn prepare_domain() -> [u8; PREPARE_DOMAIN_BYTES] {
    [111, 112, 101, 110, 97, 99, 46, 112, 114, 101, 112, 97, 114, 101, 118, 49]
}

fn show_domain() -> [u8; SHOW_DOMAIN_BYTES] {
    [111, 112, 101, 110, 97, 99, 46, 115, 104, 111, 119, 46, 118, 49]
}

fn scope_domain() -> [u8; SCOPE_DOMAIN_BYTES] {
    [111, 112, 101, 110, 97, 99, 46, 115, 99, 111, 112, 101, 46, 118, 49]
}

fn compute_prepare_commitment(
    sod_hash: [u8; HASH_BYTES],
    mrz_hash: [u8; HASH_BYTES],
    link_rand: [u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut preimage: [u8; PREPARE_DOMAIN_BYTES + HASH_BYTES * 3] =
        [0; PREPARE_DOMAIN_BYTES + HASH_BYTES * 3];
    let domain = prepare_domain();

    for i in 0..PREPARE_DOMAIN_BYTES {
        preimage[i] = domain[i];
    }

    for i in 0..HASH_BYTES {
        preimage[PREPARE_DOMAIN_BYTES + i] = sod_hash[i];
        preimage[PREPARE_DOMAIN_BYTES + HASH_BYTES + i] = mrz_hash[i];
        preimage[PREPARE_DOMAIN_BYTES + HASH_BYTES * 2 + i] = link_rand[i];
    }

    digest(preimage)
}

fn compute_challenge_digest(
    challenge: [u8; HASH_BYTES],
    prepare_commitment: [u8; HASH_BYTES],
    epoch: [u8; EPOCH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut preimage: [u8; SHOW_DOMAIN_BYTES + HASH_BYTES + HASH_BYTES + EPOCH_BYTES] =
        [0; SHOW_DOMAIN_BYTES + HASH_BYTES + HASH_BYTES + EPOCH_BYTES];
    let domain = show_domain();

    for i in 0..SHOW_DOMAIN_BYTES {
        preimage[i] = domain[i];
    }

    for i in 0..HASH_BYTES {
        preimage[SHOW_DOMAIN_BYTES + i] = challenge[i];
        preimage[SHOW_DOMAIN_BYTES + HASH_BYTES + i] = prepare_commitment[i];
    }

    for i in 0..EPOCH_BYTES {
        preimage[SHOW_DOMAIN_BYTES + HASH_BYTES + HASH_BYTES + i] = epoch[i];
    }

    digest(preimage)
}

fn compute_scoped_link_tag(
    prepare_commitment: [u8; HASH_BYTES],
    link_scope: [u8; HASH_BYTES],
    epoch: [u8; EPOCH_BYTES],
) -> [u8; HASH_BYTES] {
    let mut preimage: [u8; SCOPE_DOMAIN_BYTES + HASH_BYTES + HASH_BYTES + EPOCH_BYTES] =
        [0; SCOPE_DOMAIN_BYTES + HASH_BYTES + HASH_BYTES + EPOCH_BYTES];
    let domain = scope_domain();

    for i in 0..SCOPE_DOMAIN_BYTES {
        preimage[i] = domain[i];
    }

    for i in 0..HASH_BYTES {
        preimage[SCOPE_DOMAIN_BYTES + i] = prepare_commitment[i];
        preimage[SCOPE_DOMAIN_BYTES + HASH_BYTES + i] = link_scope[i];
    }

    for i in 0..EPOCH_BYTES {
        preimage[SCOPE_DOMAIN_BYTES + HASH_BYTES + HASH_BYTES + i] = epoch[i];
    }

    digest(preimage)
}

fn assert_hash_equals(left: [u8; HASH_BYTES], right: [u8; HASH_BYTES]) {
    for i in 0..HASH_BYTES {
        assert(left[i] == right[i], "Hash mismatch");
    }
}

fn assert_zero_hash(value: [u8; HASH_BYTES]) {
    for i in 0..HASH_BYTES {
        assert(value[i] == 0, "Expected zero hash");
    }
}

fn main(
    sod_hash: [u8; HASH_BYTES],
    mrz_hash: [u8; HASH_BYTES],
    link_rand: [u8; HASH_BYTES],
    challenge: [u8; HASH_BYTES],
    link_mode: pub bool,
    link_scope: pub [u8; HASH_BYTES],
    epoch: pub [u8; EPOCH_BYTES],
    out_prepare_commitment: pub [u8; HASH_BYTES],
    out_challenge_digest: pub [u8; HASH_BYTES],
    out_link_tag: pub [u8; HASH_BYTES],
) {
    let prepare_commitment = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
    assert_hash_equals(prepare_commitment, out_prepare_commitment);

    let challenge_digest = compute_challenge_digest(challenge, prepare_commitment, epoch);
    assert_hash_equals(challenge_digest, out_challenge_digest);

    if link_mode {
        let scoped_tag = compute_scoped_link_tag(prepare_commitment, link_scope, epoch);
        assert_hash_equals(scoped_tag, out_link_tag);
    } else {
        assert_zero_hash(link_scope);
        assert_zero_hash(out_link_tag);
    }
}

fn sample_bytes(seed: u8) -> [u8; HASH_BYTES] {
    let mut out: [u8; HASH_BYTES] = [0; HASH_BYTES];
    for i in 0..HASH_BYTES {
        out[i] = seed + (i as u8);
    }
    out
}

fn sample_epoch() -> [u8; EPOCH_BYTES] {
    [0x20, 0x26, 0x03, 0x15]
}

#[test]
fn test_show_link_recomputes_same_prepare_commitment() {
    let sod_hash = sample_bytes(1);
    let mrz_hash = sample_bytes(2);
    let link_rand = sample_bytes(3);
    let challenge = sample_bytes(4);
    let link_scope = sample_bytes(5);
    let epoch = sample_epoch();

    let prepare_commitment = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
    let challenge_digest = compute_challenge_digest(challenge, prepare_commitment, epoch);
    let scoped_tag = compute_scoped_link_tag(prepare_commitment, link_scope, epoch);

    main(
        sod_hash,
        mrz_hash,
        link_rand,
        challenge,
        true,
        link_scope,
        epoch,
        prepare_commitment,
        challenge_digest,
        scoped_tag,
    );
}

#[test]
fn test_scoped_link_tag_deterministic_in_same_scope() {
    let prepare_commitment = sample_bytes(40);
    let link_scope = sample_bytes(90);
    let epoch = sample_epoch();

    let tag_a = compute_scoped_link_tag(prepare_commitment, link_scope, epoch);
    let tag_b = compute_scoped_link_tag(prepare_commitment, link_scope, epoch);

    assert_hash_equals(tag_a, tag_b);
}

#[test]
fn test_scoped_link_tag_differs_across_scope() {
    let prepare_commitment = sample_bytes(41);
    let scope_a = sample_bytes(60);
    let scope_b = sample_bytes(61);
    let epoch = sample_epoch();

    let tag_a = compute_scoped_link_tag(prepare_commitment, scope_a, epoch);
    let tag_b = compute_scoped_link_tag(prepare_commitment, scope_b, epoch);

    let mut differs = false;
    for i in 0..HASH_BYTES {
        if tag_a[i] != tag_b[i] {
            differs = true;
        }
    }

    assert(differs, "Scoped link tag should differ across scope");
}

#[test]
fn test_unlinkable_mode_requires_zero_link_tag() {
    let sod_hash = sample_bytes(11);
    let mrz_hash = sample_bytes(12);
    let link_rand = sample_bytes(13);
    let challenge = sample_bytes(14);
    let epoch = sample_epoch();

    let prepare_commitment = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
    let challenge_digest = compute_challenge_digest(challenge, prepare_commitment, epoch);

    main(
        sod_hash,
        mrz_hash,
        link_rand,
        challenge,
        false,
        [0; HASH_BYTES],
        epoch,
        prepare_commitment,
        challenge_digest,
        [0; HASH_BYTES],
    );
}

#[test(should_fail)]
fn test_tampered_challenge_fails() {
    let sod_hash = sample_bytes(21);
    let mrz_hash = sample_bytes(22);
    let link_rand = sample_bytes(23);
    let challenge = sample_bytes(24);
    let link_scope = sample_bytes(25);
    let epoch = sample_epoch();

    let prepare_commitment = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
    let challenge_digest = compute_challenge_digest(challenge, prepare_commitment, epoch);
    let scoped_tag = compute_scoped_link_tag(prepare_commitment, link_scope, epoch);

    let mut tampered_challenge = challenge;
    tampered_challenge[0] = tampered_challenge[0] ^ 0xFF;

    main(
        sod_hash,
        mrz_hash,
        link_rand,
        tampered_challenge,
        true,
        link_scope,
        epoch,
        prepare_commitment,
        challenge_digest,
        scoped_tag,
    );
}
