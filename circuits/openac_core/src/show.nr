use sha256::digest as sha256_digest;
use std::hash::pedersen_hash;

// Domain separators for show-phase operations (ASCII byte arrays)
// "openac.show.v2" (v2 = Pedersen-based)
global SHOW_DOMAIN: [u8; 14] = [111, 112, 101, 110, 97, 99, 46, 115, 104, 111, 119, 46, 118, 50];
// "openac.scope.v2"
global SCOPE_DOMAIN: [u8; 15] = [111, 112, 101, 110, 97, 99, 46, 115, 99, 111, 112, 101, 46, 118, 50];

pub global HASH_LEN: u32 = 32;
global SHOW_DOMAIN_LEN: u32 = 14;
global SCOPE_DOMAIN_LEN: u32 = 15;
pub global EPOCH_BYTES: u32 = 4;

/// Serialize a Field element to 32 big-endian bytes.
/// Used to convert commitment coordinates into byte arrays for SHA256 hashing.
fn field_to_be_bytes(f: Field) -> [u8; 32] {
    f.to_be_bytes::<32>()
}

/// Compute challenge digest binding the verifier's challenge to this session.
///
/// Paper C2: binds verifier nonce to the credential commitment and epoch.
/// Uses SHA256 (not Pedersen) because this is a one-way digest, not a commitment.
///
/// digest = SHA256("openac.show.v2" || commitment_x || commitment_y || challenge || epoch_bytes)
pub fn compute_challenge_digest(
    commitment_x: Field,
    commitment_y: Field,
    challenge: [u8; HASH_LEN],
    epoch: [u8; EPOCH_BYTES],
) -> [u8; HASH_LEN] {
    // Preimage: domain(14) + commitment_x(32) + commitment_y(32) + challenge(32) + epoch(4) = 114 bytes
    let mut preimage: [u8; 114] = [0; 114];

    // Domain
    for i in 0..SHOW_DOMAIN_LEN {
        preimage[i] = SHOW_DOMAIN[i];
    }

    // Commitment coordinates (Grumpkin point)
    let cx_bytes = field_to_be_bytes(commitment_x);
    let cy_bytes = field_to_be_bytes(commitment_y);
    for i in 0..HASH_LEN {
        preimage[SHOW_DOMAIN_LEN + i] = cx_bytes[i];
        preimage[SHOW_DOMAIN_LEN + HASH_LEN + i] = cy_bytes[i];
    }

    // Challenge
    for i in 0..HASH_LEN {
        preimage[SHOW_DOMAIN_LEN + HASH_LEN * 2 + i] = challenge[i];
    }

    // Epoch
    for i in 0..EPOCH_BYTES {
        preimage[SHOW_DOMAIN_LEN + HASH_LEN * 3 + i] = epoch[i];
    }

    sha256_digest(preimage)
}

/// Compute scoped link tag for pseudonymous linkability within a scope+epoch.
///
/// Paper: deterministic tag that lets a verifier detect repeat presentations
/// within the same scope and epoch, without revealing the credential holder's identity.
///
/// Uses Pedersen hash (algebraic, on Grumpkin) for efficiency.
/// tag = pedersen_hash([commitment_x, commitment_y, link_scope, epoch_field])
pub fn compute_link_tag(
    commitment_x: Field,
    commitment_y: Field,
    link_scope: Field,
    epoch_field: Field,
) -> Field {
    pedersen_hash([commitment_x, commitment_y, link_scope, epoch_field])
}

/// Assert hash equality (byte-by-byte).
pub fn assert_hash_eq(left: [u8; HASH_LEN], right: [u8; HASH_LEN]) {
    for i in 0..HASH_LEN {
        assert(left[i] == right[i], "Hash mismatch");
    }
}

/// Full show-phase verification: challenge binding + scoped linking.
/// This is the generic show logic used by ALL credential types.
pub fn verify_show(
    commitment_x: Field,
    commitment_y: Field,
    challenge: [u8; HASH_LEN],
    epoch: [u8; EPOCH_BYTES],
    epoch_field: Field,
    link_mode: bool,
    link_scope: Field,
    expected_challenge_digest: [u8; HASH_LEN],
    expected_link_tag: Field,
) {
    // 0. Enforce epoch bytes == epoch_field (prevents epoch mixing attack)
    let expected_epoch_field: Field = (epoch[0] as Field) * 16777216
        + (epoch[1] as Field) * 65536
        + (epoch[2] as Field) * 256
        + (epoch[3] as Field);
    assert(epoch_field == expected_epoch_field, "epoch_field does not match epoch bytes");

    // 1. Challenge binding
    let digest = compute_challenge_digest(commitment_x, commitment_y, challenge, epoch);
    assert_hash_eq(digest, expected_challenge_digest);

    // 2. Scoped linking
    if link_mode {
        let tag = compute_link_tag(commitment_x, commitment_y, link_scope, epoch_field);
        assert(tag == expected_link_tag, "Scoped link tag mismatch");
    } else {
        assert(link_scope == 0, "Unlinkable mode requires zero scope");
        assert(expected_link_tag == 0, "Unlinkable mode requires zero tag");
    }
}

// ============================================================
// Tests
// ============================================================

fn sample_challenge() -> [u8; HASH_LEN] {
    let mut out: [u8; HASH_LEN] = [0; HASH_LEN];
    for i in 0..HASH_LEN {
        out[i] = (i as u8) + 0x40;
    }
    out
}

fn sample_epoch() -> [u8; EPOCH_BYTES] {
    [0x20, 0x26, 0x04, 0x01]
}

#[test]
fn test_challenge_digest_deterministic() {
    let d1 = compute_challenge_digest(100, 200, sample_challenge(), sample_epoch());
    let d2 = compute_challenge_digest(100, 200, sample_challenge(), sample_epoch());
    assert_hash_eq(d1, d2);
}

#[test]
fn test_challenge_digest_changes_with_commitment() {
    let d1 = compute_challenge_digest(100, 200, sample_challenge(), sample_epoch());
    let d2 = compute_challenge_digest(101, 200, sample_challenge(), sample_epoch());
    let mut differs = false;
    for i in 0..HASH_LEN {
        if d1[i] != d2[i] {
            differs = true;
        }
    }
    assert(differs, "Digest should change with different commitment");
}

#[test]
fn test_link_tag_deterministic() {
    let t1 = compute_link_tag(10, 20, 30, 40);
    let t2 = compute_link_tag(10, 20, 30, 40);
    assert(t1 == t2);
}

#[test]
fn test_link_tag_differs_across_scope() {
    let t1 = compute_link_tag(10, 20, 30, 40);
    let t2 = compute_link_tag(10, 20, 31, 40);
    assert(t1 != t2);
}

#[test]
fn test_link_tag_differs_across_epoch() {
    let t1 = compute_link_tag(10, 20, 30, 40);
    let t2 = compute_link_tag(10, 20, 30, 41);
    assert(t1 != t2);
}

#[test]
fn test_verify_show_linkable_mode() {
    let cx: Field = 555;
    let cy: Field = 666;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_field: Field = 0x20260401;
    let scope: Field = 42;

    let digest = compute_challenge_digest(cx, cy, challenge, epoch);
    let tag = compute_link_tag(cx, cy, scope, epoch_field);

    verify_show(cx, cy, challenge, epoch, epoch_field, true, scope, digest, tag);
}

#[test]
fn test_verify_show_unlinkable_mode() {
    let cx: Field = 555;
    let cy: Field = 666;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_field: Field = 0x20260401;

    let digest = compute_challenge_digest(cx, cy, challenge, epoch);

    verify_show(cx, cy, challenge, epoch, epoch_field, false, 0, digest, 0);
}

#[test(should_fail)]
fn test_verify_show_fails_on_tampered_challenge() {
    let cx: Field = 555;
    let cy: Field = 666;
    let challenge = sample_challenge();
    let epoch = sample_epoch();
    let epoch_field: Field = 0x20260401;
    let scope: Field = 42;

    let digest = compute_challenge_digest(cx, cy, challenge, epoch);
    let tag = compute_link_tag(cx, cy, scope, epoch_field);

    // Tamper challenge
    let mut bad_challenge = challenge;
    bad_challenge[0] = bad_challenge[0] ^ 0xFF;

    verify_show(cx, cy, bad_challenge, epoch, epoch_field, true, scope, digest, tag);
}
