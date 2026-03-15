use sha256::digest;

global HASH_BYTES: u32 = 32;
global PREPARE_DOMAIN_BYTES: u32 = 16;

fn prepare_domain() -> [u8; PREPARE_DOMAIN_BYTES] {
    [111, 112, 101, 110, 97, 99, 46, 112, 114, 101, 112, 97, 114, 101, 118, 49]
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

fn assert_hash_equals(
    left: [u8; HASH_BYTES],
    right: [u8; HASH_BYTES],
) {
    for i in 0..HASH_BYTES {
        assert(left[i] == right[i], "Hash mismatch");
    }
}

fn main(
    sod_hash: [u8; HASH_BYTES],
    mrz_hash: [u8; HASH_BYTES],
    link_rand: [u8; HASH_BYTES],
    out_prepare_commitment: pub [u8; HASH_BYTES],
) {
    let computed = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
    assert_hash_equals(computed, out_prepare_commitment);
}

fn sample_bytes(seed: u8) -> [u8; HASH_BYTES] {
    let mut out: [u8; HASH_BYTES] = [0; HASH_BYTES];
    for i in 0..HASH_BYTES {
        out[i] = seed + (i as u8);
    }
    out
}

#[test]
fn test_prepare_commitment_matches_expected() {
    let sod_hash = sample_bytes(10);
    let mrz_hash = sample_bytes(30);
    let link_rand = sample_bytes(90);
    let expected = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);

    main(sod_hash, mrz_hash, link_rand, expected);
}

#[test]
fn test_prepare_commitment_changes_when_link_rand_changes() {
    let sod_hash = sample_bytes(11);
    let mrz_hash = sample_bytes(31);

    let link_rand_a = sample_bytes(55);
    let link_rand_b = sample_bytes(56);

    let commitment_a = compute_prepare_commitment(sod_hash, mrz_hash, link_rand_a);
    let commitment_b = compute_prepare_commitment(sod_hash, mrz_hash, link_rand_b);

    let mut differs = false;
    for i in 0..HASH_BYTES {
        if commitment_a[i] != commitment_b[i] {
            differs = true;
        }
    }

    assert(differs, "Commitment should change when link_rand changes");
}

#[test(should_fail)]
fn test_prepare_commitment_fails_on_wrong_expected_output() {
    let sod_hash = sample_bytes(12);
    let mrz_hash = sample_bytes(32);
    let link_rand = sample_bytes(92);
    let mut wrong_expected = compute_prepare_commitment(sod_hash, mrz_hash, link_rand);
    wrong_expected[0] = wrong_expected[0] ^ 0x01;

    main(sod_hash, mrz_hash, link_rand, wrong_expected);
}
