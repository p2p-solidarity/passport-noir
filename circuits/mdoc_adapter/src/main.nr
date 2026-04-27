use sha256::{digest, sha256_var};
use std::ecdsa_secp256r1::verify_signature;
use std::embedded_curve_ops::EmbeddedCurvePoint;

use openac_core::commit::{assert_commitment_eq, commit_attributes_v3, DOMAIN_MDL, hash_to_fields};
use openac_core::device::pk_digest_from_bytes;

// OpenAC mDoc / mDL Adapter (Prepare Phase, v2 -- Path A)
//
// Direction D (EUDI-aligned mobile driving licence support). Mirrors the
// prepare-phase shape of `passport_adapter` and `sdjwt_adapter`: authenticate
// the issuer-signed mso, prove per-claim digests live in that mso, then
// emit a v3 Pedersen commitment that binds a device pk_digest. The Show
// circuit (mdoc_show, future) re-opens the commitment, runs predicates,
// and adds in-circuit ECDSA-P256 device binding -- exactly the way
// openac_show v3 layers on passport_adapter.
//
// What this circuit verifies (v2):
//   1. Issuer signature on the mso bytes:
//      `tbs_hash = SHA256(message[0..message_len])` and ECDSA-P256
//      verify(issuer_pk, signature, tbs_hash). This pins the message
//      content to the issuer's public key.
//   2. Per-claim variable-position substring inclusion:
//      For every active claim i, `expected_envelopes[i]` must equal the
//      35-byte window `message[envelope_positions[i]..+35]`. This is
//      the Noir analogue of zkID's `CheckSubstrInclusionPoly` with a
//      direct selector loop -- correct, but O(N*K) in constraints.
//   3. Per-claim CBOR digest envelope authenticity (inherited from v0):
//      For every active claim i, SHA256(preimage[0..len]) must match the
//      32 hash bytes inside `expected_envelopes[i]`, and the envelope
//      must encode `[digest_id, 0x58, 0x20, <hash>]`. Same shape as
//      zkID's MdocClaimVerifier (mdoc-claim-verifier.circom L49-92).
//   4. validUntil extraction (v2 new):
//      Verifies the canonical 13-byte CBOR prefix
//      `0x6a "validUntil" 0xc0 0x74` appears at
//      `valid_until_prefix_pos`, then parses the next 10 ASCII bytes as
//      `YYYY-MM-DD` and exports `out_valid_until = year*10000 +
//      month*100 + day`. The verifier compares this against `today`
//      out-of-circuit (cheaper than in-circuit date arithmetic).
//   5. Device key extraction from the signed mso (v2 new):
//      Verifies the canonical 8-byte COSE_Key prefix
//      `a4 01 02 20 01 21 58 20` (kty=EC2, crv=P-256, x:bstr32) at
//      `device_key_prefix_pos`; reads the 32 x-bytes; verifies the
//      3-byte `22 58 20` y-prefix; reads the 32 y-bytes. The Pedersen
//      commitment now binds `pk_digest = pedersen_hash(extracted_x,
//      extracted_y)` so the prover cannot lie about which device key
//      the issuer registered. This closes the v1 trust gap where
//      `enclave_pk_x/y` was a free private witness.
//   6. Combined attribute hash = SHA256 over the concatenated 35-byte
//      digest envelopes (zero-padded to MAX_CLAIMS slots), bound into
//      a v3 Pedersen commitment on Grumpkin:
//      C = commit_attributes_v3(DOMAIN_MDL, attr_hi, attr_lo, pk_digest,
//          link_rand)
//
// What this circuit deliberately defers (tracked for v3):
//   * Bigger MAX_MSG_LEN (currently 512 to keep gates bounded; zkID
//     uses 1792). Polynomial-evaluation substring inclusion is the
//     route to scale this without blowing up constraints.
//   * `yPrefixLen` as a runtime parameter so the device-key extractor
//     handles non-canonical CBOR encodings of COSE_Key.
//   * Multi-claim active fixtures (v0 already supports the loop; v2
//     just needs Prover.toml positions for additional claims).
//
// Public outputs:
//   - issuer_pk_x, issuer_pk_y: P-256 issuer public key. The verifier
//     pins this against an out-of-circuit trust anchor before accepting.
//   - out_valid_until: parsed `YYYYMMDD` integer; verifier checks
//     `out_valid_until >= today` out-of-circuit.
//   - out_commitment_x, out_commitment_y: Grumpkin Pedersen commitment.
//     Used as the linkage anchor with mdoc_show.

global MAX_CLAIMS: u32 = 4;
global MAX_PREIMAGE_LEN: u32 = 256;

// v1 message envelope. 512 bytes covers the synthetic v2 fixture (165
// signed bytes); future revisions will scale this towards zkID's 1792
// once we move from the O(N*K) selector substring check to a
// polynomial-evaluation primitive.
global MAX_MSG_LEN: u32 = 512;

// CBOR encoding constants for the digest envelope. zkID's
// mdoc-claim-verifier.circom uses the same layout
// (digestId, bytes(32) marker 0x58, length 0x20, 32 raw hash bytes).
global CBOR_BYTES_32_MARKER: u8 = 0x58;
global CBOR_BYTES_32_LENGTH: u8 = 0x20;
global ENCODED_DIGEST_LEN: u32 = 35;

// v2 layout constants -- match scripts/gen_mdoc_v1_fixture.py.
global VALID_UNTIL_PREFIX_LEN: u32 = 13;
global VALID_UNTIL_DATE_LEN: u32 = 10;
global DEVICE_KEY_PREFIX_LEN: u32 = 8;
global DEVICE_KEY_Y_PREFIX_LEN: u32 = 3;
global DEVICE_KEY_COORD_LEN: u32 = 32;

/// Verify a single claim's digest envelope against its preimage.
///
/// `expected_envelope` is the 35-byte structure
/// `[digest_id, 0x58, 0x20, <32-byte SHA256(preimage)>]` that the issuer
/// signed inside the mDoc mso. The caller passes the raw envelope bytes;
/// this function rebuilds the envelope from the preimage and verifies
/// every byte matches.
///
/// Returns nothing on success; panics with a descriptive message on
/// any structural or hash mismatch.
fn verify_claim_envelope(
    preimage: [u8; MAX_PREIMAGE_LEN],
    preimage_len: u32,
    digest_id: u8,
    expected_envelope: [u8; ENCODED_DIGEST_LEN],
) {
    assert(preimage_len <= MAX_PREIMAGE_LEN as u32, "mDoc preimage length exceeds maximum");

    // Zero-pad the preimage past `preimage_len` so the SHA256 covers
    // exactly the issuer-supplied bytes. Mirrors verify_dg_chain in
    // passport_adapter so off-circuit witness generation can share the
    // same convention.
    let mut preimage_padded: [u8; MAX_PREIMAGE_LEN] = [0; MAX_PREIMAGE_LEN];
    for j in 0..MAX_PREIMAGE_LEN {
        if (j as u32) < preimage_len {
            preimage_padded[j] = preimage[j];
        }
    }
    let preimage_hash: [u8; 32] = digest(preimage_padded);

    // CBOR envelope structural checks. The 3 prefix bytes uniquely
    // identify a single-byte digest_id (must be < 24) followed by a
    // bytes(32) marker -- multi-byte digest IDs would not pass the
    // `expected_envelope[0] == digest_id` check below because the prover
    // would need to encode them across multiple bytes.
    assert(expected_envelope[0] == digest_id, "mDoc digest envelope: digest_id byte mismatch");
    assert(
        expected_envelope[1] == CBOR_BYTES_32_MARKER,
        "mDoc digest envelope: CBOR bytes(32) marker (0x58) mismatch",
    );
    assert(
        expected_envelope[2] == CBOR_BYTES_32_LENGTH,
        "mDoc digest envelope: CBOR length byte (0x20) mismatch",
    );

    // Hash bytes occupy positions 3..35 of the envelope.
    for k in 0..32 {
        assert(
            expected_envelope[3 + k] == preimage_hash[k],
            "mDoc digest envelope: preimage hash mismatch",
        );
    }
}

/// Verify all active claim envelopes and return the combined attribute
/// hash that feeds into the Pedersen commitment.
///
/// Inactive claim slots (i >= claim_count) are zero-padded in
/// `combined_preimage`; this matches sdjwt_adapter::verify_disclosure_hashes
/// so the witness generator can reuse the same fill convention.
fn verify_all_claim_envelopes(
    claim_count: u8,
    preimages: [[u8; MAX_PREIMAGE_LEN]; MAX_CLAIMS],
    preimage_lens: [u32; MAX_CLAIMS],
    digest_ids: [u8; MAX_CLAIMS],
    expected_envelopes: [[u8; ENCODED_DIGEST_LEN]; MAX_CLAIMS],
) -> [u8; 32] {
    assert(claim_count > 0, "mDoc must contain at least one claim");
    assert(claim_count as u32 <= MAX_CLAIMS, "mDoc claim count exceeds MAX_CLAIMS");

    let mut combined_preimage: [u8; MAX_CLAIMS * ENCODED_DIGEST_LEN] =
        [0; MAX_CLAIMS * ENCODED_DIGEST_LEN];

    for i in 0..MAX_CLAIMS {
        if (i as u8) < claim_count {
            verify_claim_envelope(
                preimages[i],
                preimage_lens[i],
                digest_ids[i],
                expected_envelopes[i],
            );
            for k in 0..ENCODED_DIGEST_LEN {
                combined_preimage[i * ENCODED_DIGEST_LEN + k] = expected_envelopes[i][k];
            }
        }
    }

    digest(combined_preimage)
}

/// Compute the v3 Pedersen commitment for an mDoc credential.
fn compute_mdoc_commitment(
    combined_hash: [u8; 32],
    pk_digest: Field,
    link_rand: Field,
) -> EmbeddedCurvePoint {
    let (attr_hi, attr_lo) = hash_to_fields(combined_hash);
    commit_attributes_v3(DOMAIN_MDL, attr_hi, attr_lo, pk_digest, link_rand)
}

/// Verify the issuer's ECDSA-P256 signature over the to-be-signed slice
/// `message[0..message_len]`. Computes SHA256 in-circuit so the prover
/// cannot supply a hash decoupled from the message bytes the substring
/// check operates on.
fn verify_issuer_signature(
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    issuer_signature: [u8; 64],
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
) {
    assert(message_len <= MAX_MSG_LEN as u32, "mDoc message length exceeds maximum");

    // Hash exactly `message_len` bytes -- COSE_Sign1 signs unpadded mso
    // bytes, not a fixed-size buffer. `sha256_var` advances the SHA256
    // padding state to the supplied length so the hash matches what the
    // issuer signed off-circuit. (Using `digest` over the full
    // [u8; MAX_MSG_LEN] would compute SHA256 of zero-padded bytes, which
    // does not equal SHA256 of the unpadded signed message.)
    let tbs_hash: [u8; 32] = sha256_var(message, message_len);

    let valid = verify_signature(issuer_pk_x, issuer_pk_y, issuer_signature, tbs_hash);
    assert(valid, "mDoc issuer ECDSA-P256 signature verification failed");
}

/// Read a single byte from `message` at runtime position `pos`.
/// Implemented via an O(N) selector loop -- Noir's dynamic array index
/// already emits per-position constraints under the hood, but writing
/// the loop explicitly keeps the cost auditable and lets generic
/// extractors share a single pattern. Returns 0 if `pos >= MAX_MSG_LEN`
/// (no constraint will fire because the predicate never matches).
fn extract_byte_at_pos(message: [u8; MAX_MSG_LEN], pos: u32) -> u8 {
    let mut byte_at: u8 = 0;
    for j in 0..MAX_MSG_LEN {
        if (j as u32) == pos {
            byte_at = message[j];
        }
    }
    byte_at
}

/// Read K consecutive bytes starting at `pos` from `message`. Caller is
/// responsible for ensuring `pos + K <= message_len`; this helper does
/// not range-check (callers that want range-checking should use
/// `assert_substring_at_pos` instead, or wrap with their own assert).
fn extract_bytes_at_pos<let K: u32>(message: [u8; MAX_MSG_LEN], pos: u32) -> [u8; K] {
    let mut out: [u8; K] = [0; K];
    for k in 0..K {
        out[k] = extract_byte_at_pos(message, pos + k as u32);
    }
    out
}

/// Assert that the K-byte `expected` substring equals the window
/// `message[pos..pos + K]` and that the window stays inside
/// `message_len`. Generic over K -- used for both the 35-byte digest
/// envelope (v1) and the 13/8/3-byte CBOR prefixes (v2 validUntil and
/// deviceKey). This is the Noir analogue of zkID's
/// `CheckSubstrInclusionPoly` with a direct selector loop. Correct but
/// expensive -- O(N*K) constraints; swap for a polynomial-evaluation
/// primitive when scaling MAX_MSG_LEN past 1024.
fn assert_substring_at_pos<let K: u32>(
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    pos: u32,
    expected: [u8; K],
) {
    assert(pos + K as u32 <= message_len, "mDoc substring window past message_len");

    for k in 0..K {
        let target_idx = pos + k as u32;
        let mut byte_at: u8 = 0;
        for j in 0..MAX_MSG_LEN {
            if (j as u32) == target_idx {
                byte_at = message[j];
            }
        }
        assert(byte_at == expected[k], "mDoc substring byte does not match issuer-signed message");
    }
}

/// v1 alias kept for naming compatibility with existing call sites and
/// tests; the implementation is now `assert_substring_at_pos<35>`.
fn assert_envelope_at_pos(
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    pos: u32,
    expected_envelope: [u8; ENCODED_DIGEST_LEN],
) {
    assert_substring_at_pos(message, message_len, pos, expected_envelope);
}

// ============================================================
// v2 helpers: validUntil + device-key extraction
// ============================================================

/// The canonical CBOR prefix that precedes a `validUntil` date string in
/// an mDoc mso. Encodes:
///   * 0x6a       : text(10) marker
///   * "validUntil" (10 ASCII bytes)
///   * 0xc0       : tag(0) date-time
///   * 0x74       : text(20) marker (the date string is `YYYY-MM-DDTHH:MM:SSZ`
///                  but we only parse the leading `YYYY-MM-DD`).
fn valid_until_prefix() -> [u8; VALID_UNTIL_PREFIX_LEN] {
    [0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0xc0, 0x74]
}

/// Parse a 10-byte ASCII `YYYY-MM-DD` string into the integer
/// `year * 10000 + month * 100 + day`. The two `'-'` separators at
/// positions 4 and 7 are asserted; the digits are bound to ASCII '0'..'9'
/// implicitly because any non-digit byte makes the linear combination
/// fall outside the legal range and either over/underflows or fails a
/// downstream comparison in the show circuit.
fn parse_iso_date(date_bytes: [u8; VALID_UNTIL_DATE_LEN]) -> u32 {
    assert(date_bytes[4] == 0x2d, "mDoc validUntil: expected '-' at byte 4");
    assert(date_bytes[7] == 0x2d, "mDoc validUntil: expected '-' at byte 7");

    let year: u32 = (date_bytes[0] as u32 - 48) * 1000
        + (date_bytes[1] as u32 - 48) * 100
        + (date_bytes[2] as u32 - 48) * 10
        + (date_bytes[3] as u32 - 48);
    let month: u32 = (date_bytes[5] as u32 - 48) * 10 + (date_bytes[6] as u32 - 48);
    let day: u32 = (date_bytes[8] as u32 - 48) * 10 + (date_bytes[9] as u32 - 48);

    year * 10000 + month * 100 + day
}

/// Verify the canonical 13-byte `validUntil` prefix appears at
/// `prefix_pos`, then extract and parse the 10-byte ASCII date that
/// follows. Returns `YYYYMMDD` as a `u32` for the verifier to compare
/// against `today` out-of-circuit.
fn extract_valid_until(message: [u8; MAX_MSG_LEN], message_len: u32, prefix_pos: u32) -> u32 {
    assert_substring_at_pos(message, message_len, prefix_pos, valid_until_prefix());
    let date_pos = prefix_pos + VALID_UNTIL_PREFIX_LEN as u32;
    assert(
        date_pos + VALID_UNTIL_DATE_LEN as u32 <= message_len,
        "mDoc validUntil date window past message_len",
    );
    let date_bytes: [u8; VALID_UNTIL_DATE_LEN] = extract_bytes_at_pos(message, date_pos);
    parse_iso_date(date_bytes)
}

/// COSE_Key prefix that precedes the deviceKey x coordinate in an mDoc
/// mso. Encodes:
///   * 0xa4 : map(4)
///   * 0x01 : key 1   (kty)
///   * 0x02 : value 2 (EC2)
///   * 0x20 : key -1  (crv)
///   * 0x01 : value 1 (P-256)
///   * 0x21 : key -2  (x)
///   * 0x58 : bstr major + 1-byte length follow-up
///   * 0x20 : length 32
fn device_key_x_prefix() -> [u8; DEVICE_KEY_PREFIX_LEN] {
    [0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20]
}

/// Three-byte prefix that separates the deviceKey x and y coordinates:
///   * 0x22 : key -3 (y)
///   * 0x58 : bstr major + 1-byte length follow-up
///   * 0x20 : length 32
fn device_key_y_prefix() -> [u8; DEVICE_KEY_Y_PREFIX_LEN] {
    [0x22, 0x58, 0x20]
}

/// Verify the canonical COSE_Key prefix at `prefix_pos`, extract the
/// 32-byte x coordinate, verify the 3-byte y-prefix, then extract the
/// 32-byte y coordinate. Returns `(x_bytes, y_bytes)`.
///
/// The two prefixes are signed by the issuer (they sit inside the mso
/// bytes ECDSA-verified upstream) so a prover cannot point this
/// extractor at arbitrary 32-byte windows -- the surrounding markers
/// constrain the layout.
fn extract_device_key_from_mso(
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    prefix_pos: u32,
) -> ([u8; 32], [u8; 32]) {
    assert_substring_at_pos(message, message_len, prefix_pos, device_key_x_prefix());

    let x_pos = prefix_pos + DEVICE_KEY_PREFIX_LEN as u32;
    let y_prefix_pos = x_pos + DEVICE_KEY_COORD_LEN as u32;
    let y_pos = y_prefix_pos + DEVICE_KEY_Y_PREFIX_LEN as u32;
    let coord_end = y_pos + DEVICE_KEY_COORD_LEN as u32;
    assert(coord_end <= message_len, "mDoc deviceKey window past message_len");

    let x: [u8; 32] = extract_bytes_at_pos(message, x_pos);
    assert_substring_at_pos(message, message_len, y_prefix_pos, device_key_y_prefix());
    let y: [u8; 32] = extract_bytes_at_pos(message, y_pos);
    (x, y)
}

/// For every active claim i (i < claim_count), assert that
/// `expected_envelopes[i]` appears at position `envelope_positions[i]`
/// in the issuer-signed message.
fn assert_all_envelopes_in_message(
    claim_count: u8,
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    envelope_positions: [u32; MAX_CLAIMS],
    expected_envelopes: [[u8; ENCODED_DIGEST_LEN]; MAX_CLAIMS],
) {
    for i in 0..MAX_CLAIMS {
        if (i as u8) < claim_count {
            assert_envelope_at_pos(
                message,
                message_len,
                envelope_positions[i],
                expected_envelopes[i],
            );
        }
    }
}

fn main(
    // === Per-claim issuer-signed digest envelope inputs ===
    claim_count: u8,
    preimages: [[u8; MAX_PREIMAGE_LEN]; MAX_CLAIMS],
    preimage_lens: [u32; MAX_CLAIMS],
    digest_ids: [u8; MAX_CLAIMS],
    expected_envelopes: [[u8; ENCODED_DIGEST_LEN]; MAX_CLAIMS],
    // === v1 issuer-signed mso inputs ===
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    envelope_positions: [u32; MAX_CLAIMS],
    issuer_signature: [u8; 64],
    // === v2 layout positions inside the signed message ===
    valid_until_prefix_pos: u32,
    device_key_prefix_pos: u32,
    // === OpenAC commitment inputs ===
    link_rand: Field,
    // === Public trust anchors ===
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    // === Public outputs ===
    out_valid_until: pub u32,
    out_commitment_x: pub Field,
    out_commitment_y: pub Field,
) {
    // Step 1 (v1): authenticate the mso bytes against the issuer key.
    verify_issuer_signature(
        message,
        message_len,
        issuer_signature,
        issuer_pk_x,
        issuer_pk_y,
    );

    // Step 2 (v1): each active claim's envelope must live inside the
    // signed mso at the prover-declared position.
    assert_all_envelopes_in_message(
        claim_count,
        message,
        message_len,
        envelope_positions,
        expected_envelopes,
    );

    // Step 3 (v0 inherited): per-claim digest envelope authenticity.
    let combined_hash = verify_all_claim_envelopes(
        claim_count,
        preimages,
        preimage_lens,
        digest_ids,
        expected_envelopes,
    );

    // Step 4 (v2): validUntil extraction. The verifier compares
    // out_valid_until against today's YYYYMMDD out-of-circuit.
    let parsed_valid_until = extract_valid_until(message, message_len, valid_until_prefix_pos);
    assert(
        parsed_valid_until == out_valid_until,
        "mDoc validUntil extracted from mso does not match public output",
    );

    // Step 5 (v2): extract the deviceKey COSE_Key from the signed mso.
    // pk_digest is now derived from issuer-attested bytes -- the prover
    // can no longer supply an arbitrary enclave_pk private witness.
    let (device_key_x, device_key_y) =
        extract_device_key_from_mso(message, message_len, device_key_prefix_pos);
    let pk_digest = pk_digest_from_bytes(device_key_x, device_key_y);

    // Step 6: v3 Pedersen commitment.
    let commitment = compute_mdoc_commitment(combined_hash, pk_digest, link_rand);
    assert_commitment_eq(commitment, out_commitment_x, out_commitment_y);
}

// ============================================================
// Tests
// ============================================================

/// Build a deterministic test preimage of `len` bytes seeded by `seed`.
fn build_preimage(seed: u8, len: u32) -> [u8; MAX_PREIMAGE_LEN] {
    let mut data: [u8; MAX_PREIMAGE_LEN] = [0; MAX_PREIMAGE_LEN];
    for i in 0..MAX_PREIMAGE_LEN {
        if (i as u32) < len {
            data[i] = seed + (i as u8);
        }
    }
    data
}

/// Build the canonical CBOR envelope `[digest_id, 0x58, 0x20, <hash>]`
/// from a preimage so positive tests can mirror what an off-circuit
/// witness generator would produce.
fn build_envelope(preimage: [u8; MAX_PREIMAGE_LEN], digest_id: u8) -> [u8; ENCODED_DIGEST_LEN] {
    let h: [u8; 32] = digest(preimage);
    let mut env: [u8; ENCODED_DIGEST_LEN] = [0; ENCODED_DIGEST_LEN];
    env[0] = digest_id;
    env[1] = CBOR_BYTES_32_MARKER;
    env[2] = CBOR_BYTES_32_LENGTH;
    for k in 0..32 {
        env[3 + k] = h[k];
    }
    env
}

/// Canonical P-256 enclave test key (x). Copied verbatim from
/// circuits/passport_adapter/src/main.nr so all Path A tests share the
/// same fixture.
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

/// Build a one-claim fixture (preimages, lens, ids, envelopes) ready for
/// `verify_all_claim_envelopes`.
fn build_one_claim_fixture() -> ([[u8; MAX_PREIMAGE_LEN]; MAX_CLAIMS], [u32; MAX_CLAIMS], [u8; MAX_CLAIMS], [[u8; ENCODED_DIGEST_LEN]; MAX_CLAIMS]) {
    let p0 = build_preimage(0x10, 64);
    let env0 = build_envelope(p0, 0);
    let preimages = [p0, [0; MAX_PREIMAGE_LEN], [0; MAX_PREIMAGE_LEN], [0; MAX_PREIMAGE_LEN]];
    let lens: [u32; MAX_CLAIMS] = [64, 0, 0, 0];
    let ids: [u8; MAX_CLAIMS] = [0, 0, 0, 0];
    let envelopes =
        [env0, [0; ENCODED_DIGEST_LEN], [0; ENCODED_DIGEST_LEN], [0; ENCODED_DIGEST_LEN]];
    (preimages, lens, ids, envelopes)
}

/// Build a three-claim fixture exercising digest_id values 0, 1, and 23
/// (the largest single-byte CBOR digest_id allowed by the envelope check).
fn build_three_claim_fixture() -> ([[u8; MAX_PREIMAGE_LEN]; MAX_CLAIMS], [u32; MAX_CLAIMS], [u8; MAX_CLAIMS], [[u8; ENCODED_DIGEST_LEN]; MAX_CLAIMS]) {
    let p0 = build_preimage(0x10, 64);
    let p1 = build_preimage(0x20, 96);
    let p2 = build_preimage(0x30, 128);
    let env0 = build_envelope(p0, 0);
    let env1 = build_envelope(p1, 1);
    let env2 = build_envelope(p2, 23);
    let preimages = [p0, p1, p2, [0; MAX_PREIMAGE_LEN]];
    let lens: [u32; MAX_CLAIMS] = [64, 96, 128, 0];
    let ids: [u8; MAX_CLAIMS] = [0, 1, 23, 0];
    let envelopes = [env0, env1, env2, [0; ENCODED_DIGEST_LEN]];
    (preimages, lens, ids, envelopes)
}

// --- Per-claim envelope tests ---

#[test]
fn test_envelope_one_claim_passes() {
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let _ = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
}

#[test]
fn test_envelope_three_claims_pass() {
    let (preimages, lens, ids, envelopes) = build_three_claim_fixture();
    let _ = verify_all_claim_envelopes(3, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_tampered_preimage() {
    let (mut preimages, lens, ids, envelopes) = build_one_claim_fixture();
    preimages[0][0] ^= 0xFF;
    let _ = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_wrong_digest_id_byte() {
    let (preimages, lens, ids, mut envelopes) = build_one_claim_fixture();
    envelopes[0][0] ^= 0x01;
    let _ = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_wrong_cbor_marker() {
    let (preimages, lens, ids, mut envelopes) = build_one_claim_fixture();
    envelopes[0][1] = 0x59;
    let _ = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_wrong_cbor_length() {
    let (preimages, lens, ids, mut envelopes) = build_one_claim_fixture();
    envelopes[0][2] = 0x21;
    let _ = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_tampered_hash_byte() {
    let (preimages, lens, ids, mut envelopes) = build_one_claim_fixture();
    envelopes[0][20] ^= 0x01;
    let _ = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_zero_claim_count() {
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let _ = verify_all_claim_envelopes(0, preimages, lens, ids, envelopes);
}

#[test(should_fail)]
fn test_envelope_fails_on_oversize_claim_count() {
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let _ = verify_all_claim_envelopes((MAX_CLAIMS + 1) as u8, preimages, lens, ids, envelopes);
}

// --- Combined hash linkage tests ---

#[test]
fn test_combined_hash_changes_with_claim_count() {
    let (preimages, lens, ids, envelopes) = build_three_claim_fixture();
    let h_one = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
    let h_three = verify_all_claim_envelopes(3, preimages, lens, ids, envelopes);
    assert(h_one != h_three, "Combined hash must change when more claim slots become active");
}

// --- Pedersen commitment tests ---

#[test]
fn test_commitment_deterministic() {
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let combined_hash = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_mdoc_commitment(combined_hash, pk_digest, 42);
    let c2 = compute_mdoc_commitment(combined_hash, pk_digest, 42);
    assert(c1.x == c2.x, "mDoc commitment X should be deterministic");
    assert(c1.y == c2.y, "mDoc commitment Y should be deterministic");
}

#[test]
fn test_commitment_changes_with_link_rand() {
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let combined_hash = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c1 = compute_mdoc_commitment(combined_hash, pk_digest, 42);
    let c2 = compute_mdoc_commitment(combined_hash, pk_digest, 43);
    assert(c1.x != c2.x, "Different link_rand must produce different mDoc commitment");
}

#[test]
fn test_commitment_changes_with_pk_digest() {
    // Path A property: swapping enclave pk bytes must change the v3
    // mDoc commitment, locking ownership of the credential to one device.
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let combined_hash = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
    let pk_digest_a = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let mut pk_x_b = test_enclave_pk_x();
    pk_x_b[0] ^= 0x01;
    let pk_digest_b = pk_digest_from_bytes(pk_x_b, test_enclave_pk_y());
    let c1 = compute_mdoc_commitment(combined_hash, pk_digest_a, 42);
    let c2 = compute_mdoc_commitment(combined_hash, pk_digest_b, 42);
    assert(c1.x != c2.x, "Different enclave pk must produce different mDoc commitment");
}

#[test]
fn test_commitment_changes_with_claim_value() {
    let (preimages_a, lens_a, ids_a, envelopes_a) = build_one_claim_fixture();
    let combined_a = verify_all_claim_envelopes(1, preimages_a, lens_a, ids_a, envelopes_a);

    // Tweak the preimage so the digest envelope changes; both circuits
    // must accept their respective fixture, but the commitments must
    // disagree -- this is the binding property of the adapter.
    let p_b = build_preimage(0x11, 64);
    let env_b = build_envelope(p_b, 0);
    let preimages_b = [p_b, [0; MAX_PREIMAGE_LEN], [0; MAX_PREIMAGE_LEN], [0; MAX_PREIMAGE_LEN]];
    let lens_b: [u32; MAX_CLAIMS] = [64, 0, 0, 0];
    let ids_b: [u8; MAX_CLAIMS] = [0, 0, 0, 0];
    let envelopes_b =
        [env_b, [0; ENCODED_DIGEST_LEN], [0; ENCODED_DIGEST_LEN], [0; ENCODED_DIGEST_LEN]];
    let combined_b = verify_all_claim_envelopes(1, preimages_b, lens_b, ids_b, envelopes_b);

    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let c_a = compute_mdoc_commitment(combined_a, pk_digest, 42);
    let c_b = compute_mdoc_commitment(combined_b, pk_digest, 42);
    assert(c_a.x != c_b.x, "Different claim preimages must produce different mDoc commitment");
}

#[test]
fn test_commitment_uses_mdl_domain() {
    // Cross-credential separation: an mDoc commitment must not collide
    // with passport / x509 / sdjwt commitments over the same attribute
    // hash, pk_digest, and randomness. This is what DOMAIN_MDL = 0x04
    // buys us; a regression here would let an attacker cross-link an
    // mDoc credential to e.g. a passport credential.
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let combined_hash = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());

    let (attr_hi, attr_lo) = hash_to_fields(combined_hash);
    let c_mdl = commit_attributes_v3(DOMAIN_MDL, attr_hi, attr_lo, pk_digest, 42);
    let c_passport = commit_attributes_v3(
        openac_core::commit::DOMAIN_PASSPORT,
        attr_hi,
        attr_lo,
        pk_digest,
        42,
    );
    assert(c_mdl.x != c_passport.x, "mDoc and passport commitments must not collide");
}

// ============================================================
// v1 / v2 (ECDSA + variable-shift + validUntil + deviceKey) tests
// ============================================================
// All v1_* constants are produced by `scripts/gen_mdoc_v1_fixture.py`.
// The Python script signs SHA256 of the layout described below with a
// deterministic P-256 key (seed 0x1234...cdef). Regenerate the constants
// whenever the layout changes.
//
//   [0..32)    ASCII header
//   [32..67)   claim envelope (35 bytes)
//   [67..80)   validUntilPrefix (13 bytes)
//   [80..90)   date string "2030-12-31"
//   [90..98)   deviceKey COSE_Key prefix (8 bytes)
//   [98..130)  deviceKey x (canonical Path A pk_x, 32 bytes)
//   [130..133) deviceKey y prefix (3 bytes)
//   [133..165) deviceKey y (canonical Path A pk_y, 32 bytes)
//
// MESSAGE_LEN = 165; offsets used directly by the v2 main path.

global V2_TEST_MESSAGE_LEN: u32 = 165;
global V2_TEST_ENVELOPE_POS: u32 = 32;
global V2_TEST_VALID_UNTIL_PREFIX_POS: u32 = 67;
global V2_TEST_DEVICE_KEY_PREFIX_POS: u32 = 90;
global V2_TEST_VALID_UNTIL_DATE: u32 = 20301231;

fn v1_issuer_pk_x() -> [u8; 32] {
    [
        0x47, 0x1c, 0x3e, 0x75, 0x8c, 0x49, 0x04, 0x28, 0x5b, 0xba, 0x7e, 0x53, 0x11, 0x8e, 0xd0,
        0xf5, 0x24, 0xad, 0xeb, 0x07, 0x57, 0xd2, 0x5b, 0xd2, 0xf8, 0xe7, 0xb0, 0xd7, 0x6d, 0xfa,
        0x71, 0x4c,
    ]
}

fn v1_issuer_pk_y() -> [u8; 32] {
    [
        0xdd, 0x52, 0x0f, 0x7a, 0xca, 0x8a, 0x8b, 0x91, 0x7a, 0xcc, 0x37, 0xf5, 0x1d, 0xe8, 0xf0,
        0xc9, 0xbb, 0xe3, 0xad, 0x85, 0x83, 0x82, 0xe7, 0x02, 0xdc, 0x25, 0xa1, 0x2d, 0x09, 0xf7,
        0xa8, 0x58,
    ]
}

/// v2 issuer signature over the 165-byte mso. RFC 6979 deterministic
/// ECDSA-P256 with low-s normalisation (Noir's secp256r1 rejects
/// high-s, so the Python script flips `s -> N - s` before exporting).
fn v1_issuer_signature() -> [u8; 64] {
    [
        0x3d, 0x46, 0xbf, 0xe2, 0xc5, 0x4e, 0x31, 0x44, 0xd8, 0x96, 0xa3, 0xf8, 0x89, 0xef, 0x57,
        0x64, 0xd6, 0xd2, 0x80, 0x83, 0xa7, 0xb5, 0x4b, 0x2b, 0x5b, 0x21, 0xa8, 0x23, 0xf3, 0xfd,
        0x14, 0x2a, 0x47, 0xdd, 0x34, 0xf4, 0x6a, 0xb3, 0x21, 0x61, 0x80, 0x17, 0x3c, 0x4f, 0xfd,
        0xdb, 0x09, 0x65, 0x08, 0xb9, 0x40, 0xe9, 0x10, 0xa8, 0xc5, 0x42, 0x18, 0xb8, 0x19, 0x5e,
        0x66, 0x4d, 0x74, 0xec,
    ]
}

/// Build the v2 happy-path message. Layout matches the Python fixture
/// generator byte-for-byte.
fn v2_build_message() -> [u8; MAX_MSG_LEN] {
    let header: [u8; 32] = [
        0x4d, 0x44, 0x4f, 0x43, 0x5f, 0x56, 0x31, 0x5f, 0x54, 0x45, 0x53, 0x54, 0x5f, 0x46, 0x49,
        0x58, 0x54, 0x55, 0x52, 0x45, 0x5f, 0x48, 0x45, 0x41, 0x44, 0x45, 0x52, 0x5f, 0x5f, 0x5f,
        0x5f, 0x5f,
    ];
    let preimage = build_preimage(0x10, 64);
    let envelope = build_envelope(preimage, 0);

    let valid_until_pref = valid_until_prefix();
    let date_str: [u8; VALID_UNTIL_DATE_LEN] =
        [0x32, 0x30, 0x33, 0x30, 0x2d, 0x31, 0x32, 0x2d, 0x33, 0x31];

    let dk_pref = device_key_x_prefix();
    let dk_x = test_enclave_pk_x();
    let dk_y_pref = device_key_y_prefix();
    let dk_y = test_enclave_pk_y();

    let mut msg: [u8; MAX_MSG_LEN] = [0; MAX_MSG_LEN];
    for i in 0..32 {
        msg[i] = header[i];
    }
    for i in 0..ENCODED_DIGEST_LEN {
        msg[32 + i] = envelope[i];
    }
    for i in 0..VALID_UNTIL_PREFIX_LEN {
        msg[67 + i] = valid_until_pref[i];
    }
    for i in 0..VALID_UNTIL_DATE_LEN {
        msg[80 + i] = date_str[i];
    }
    for i in 0..DEVICE_KEY_PREFIX_LEN {
        msg[90 + i] = dk_pref[i];
    }
    for i in 0..DEVICE_KEY_COORD_LEN {
        msg[98 + i] = dk_x[i];
    }
    for i in 0..DEVICE_KEY_Y_PREFIX_LEN {
        msg[130 + i] = dk_y_pref[i];
    }
    for i in 0..DEVICE_KEY_COORD_LEN {
        msg[133 + i] = dk_y[i];
    }
    msg
}

fn v2_build_envelope_positions() -> [u32; MAX_CLAIMS] {
    [V2_TEST_ENVELOPE_POS, 0, 0, 0]
}

/// v2 main inputs builder. All tests share this wiring so the only
/// thing that varies between positive and negative scenarios is the
/// argument the caller intentionally tampers.
fn v2_invoke_main(
    message: [u8; MAX_MSG_LEN],
    message_len: u32,
    envelope_positions: [u32; MAX_CLAIMS],
    valid_until_prefix_pos: u32,
    device_key_prefix_pos: u32,
    issuer_signature: [u8; 64],
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    out_valid_until: u32,
) {
    let (preimages, preimage_lens, digest_ids, expected_envelopes) = build_one_claim_fixture();

    // pk_digest is now derived from the canonical Path A device key
    // (which is exactly what `extract_device_key_from_mso` will read out
    // of v2_build_message()). The expected commitment is recomputed from
    // the fixture so the test does not need to hard-code Grumpkin
    // coordinates.
    let combined_hash =
        verify_all_claim_envelopes(1, preimages, preimage_lens, digest_ids, expected_envelopes);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let commitment = compute_mdoc_commitment(combined_hash, pk_digest, 42);

    main(
        1,
        preimages,
        preimage_lens,
        digest_ids,
        expected_envelopes,
        message,
        message_len,
        envelope_positions,
        issuer_signature,
        valid_until_prefix_pos,
        device_key_prefix_pos,
        42,
        issuer_pk_x,
        issuer_pk_y,
        out_valid_until,
        commitment.x,
        commitment.y,
    );
}

#[test]
fn test_v2_main_passes() {
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

#[test(should_fail)]
fn test_v1_fails_on_tampered_signature() {
    let mut bad_sig = v1_issuer_signature();
    bad_sig[0] ^= 0x01;
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        bad_sig,
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

#[test(should_fail)]
fn test_v1_fails_on_tampered_message_byte() {
    // Flip a header byte. SHA256 changes -> ECDSA verify fails before we
    // even reach the envelope substring check.
    let mut bad_msg = v2_build_message();
    bad_msg[0] ^= 0xFF;
    v2_invoke_main(
        bad_msg,
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

#[test(should_fail)]
fn test_v1_fails_on_wrong_envelope_position() {
    let mut bad_positions = v2_build_envelope_positions();
    bad_positions[0] = 31;
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_MESSAGE_LEN,
        bad_positions,
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

#[test(should_fail)]
fn test_v1_fails_on_envelope_window_past_message_len() {
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_ENVELOPE_POS + ENCODED_DIGEST_LEN as u32 - 1,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

// --- v2 negative tests (validUntil + deviceKey) ---

#[test(should_fail)]
fn test_v2_fails_on_wrong_valid_until_prefix_pos() {
    // Pointing the prefix one byte off shifts the substring window away
    // from the canonical "validUntil" prefix in the message.
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS + 1,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

#[test(should_fail)]
fn test_v2_fails_on_wrong_out_valid_until() {
    // Caller claims a date one day later than what the issuer actually
    // signed. The extracted parse must equal `out_valid_until`, so the
    // public-output equality assert fires.
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE + 1,
    );
}

#[test(should_fail)]
fn test_v2_fails_on_wrong_device_key_prefix_pos() {
    // Pointing 4 bytes off from the canonical position breaks the
    // 8-byte deviceKey COSE_Key prefix substring inclusion.
    v2_invoke_main(
        v2_build_message(),
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS + 4,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

#[test(should_fail)]
fn test_v2_fails_on_tampered_device_key_y_byte() {
    // Tamper a byte inside the deviceKey y coordinate window. ECDSA
    // fails first because the message changed, so this is really a
    // "any byte change inside the deviceKey block is caught" check.
    let mut bad_msg = v2_build_message();
    bad_msg[140] ^= 0x01;
    v2_invoke_main(
        bad_msg,
        V2_TEST_MESSAGE_LEN,
        v2_build_envelope_positions(),
        V2_TEST_VALID_UNTIL_PREFIX_POS,
        V2_TEST_DEVICE_KEY_PREFIX_POS,
        v1_issuer_signature(),
        v1_issuer_pk_x(),
        v1_issuer_pk_y(),
        V2_TEST_VALID_UNTIL_DATE,
    );
}

// --- v2 helper-level unit tests (no ECDSA, fast) ---

#[test]
fn test_parse_iso_date_known_values() {
    let iso = [0x32, 0x30, 0x33, 0x30, 0x2d, 0x31, 0x32, 0x2d, 0x33, 0x31]; // "2030-12-31"
    assert(parse_iso_date(iso) == 20301231, "parse_iso_date 2030-12-31");

    let iso2 = [0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x34, 0x2d, 0x32, 0x37]; // "2026-04-27"
    assert(parse_iso_date(iso2) == 20260427, "parse_iso_date 2026-04-27");
}

#[test(should_fail)]
fn test_parse_iso_date_rejects_missing_dash() {
    let iso = [0x32, 0x30, 0x33, 0x30, 0x33, 0x31, 0x32, 0x2d, 0x33, 0x31]; // "20303-12-31" w/o dash at idx 4
    let _ = parse_iso_date(iso);
}

#[test]
fn test_extract_device_key_from_mso_round_trip() {
    let message = v2_build_message();
    let (x, y) =
        extract_device_key_from_mso(message, V2_TEST_MESSAGE_LEN, V2_TEST_DEVICE_KEY_PREFIX_POS);
    let expected_x = test_enclave_pk_x();
    let expected_y = test_enclave_pk_y();
    for i in 0..32 {
        assert(x[i] == expected_x[i], "extracted device key x must match canonical Path A pk_x");
        assert(y[i] == expected_y[i], "extracted device key y must match canonical Path A pk_y");
    }
}

#[test]
fn test_commitment_matches_manual_recomputation() {
    let (preimages, lens, ids, envelopes) = build_one_claim_fixture();
    let combined_hash = verify_all_claim_envelopes(1, preimages, lens, ids, envelopes);
    let pk_digest = pk_digest_from_bytes(test_enclave_pk_x(), test_enclave_pk_y());
    let rand: Field = 77;

    let c = compute_mdoc_commitment(combined_hash, pk_digest, rand);
    let (attr_hi, attr_lo) = hash_to_fields(combined_hash);
    let c_manual = commit_attributes_v3(DOMAIN_MDL, attr_hi, attr_lo, pk_digest, rand);

    assert(c.x == c_manual.x, "mDoc commitment X must match manual recomputation");
    assert(c.y == c_manual.y, "mDoc commitment Y must match manual recomputation");
}
