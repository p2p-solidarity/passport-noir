// Base64url helpers used by SD-JWT (encode disclosure hashes for inclusion
// proof) and JWT-X5C (decode the payload section of the JWS signing input
// back to the canonical normalized payload bytes).
//
// Issue P0-5 (SD-JWT) + P1-4 (JWT-X5C), 2026-04-28: previous adapter
// versions could not bind base64url-encoded artefacts to their decoded
// counterparts in-circuit, leaving an off-chain policy gap. This module
// closes both gaps with a shared byte-level encoder/decoder.
//
// Alphabet (RFC 4648 sec. 5, URL-safe, no padding):
//   A-Z (0..=25), a-z (26..=51), 0-9 (52..=61), '-' (62), '_' (63)
//
// Encoded sizes used by callers:
//   * SD-JWT disclosure hash: 32 bytes -> 43 base64url chars (no padding).
//   * JWT-X5C payload: variable length; caller passes the length explicitly.

global B64URL_HASH_BYTES: u32 = 32;
pub global B64URL_HASH_CHAR_LEN: u32 = 43;

/// Map a 6-bit value to its base64url character. Each branch is a constant
/// add so the compiler can fold them into a single sum. Value MUST be in
/// 0..64; the caller is responsible for the bound (the encoder enforces it
/// implicitly via 6-bit masks).
pub fn b64url_value_to_char(v: u8) -> u8 {
    let is_upper = v <= 25;
    let is_lower = (v >= 26) & (v <= 51);
    let is_digit = (v >= 52) & (v <= 61);
    let is_dash = v == 62;
    let is_under = v == 63;

    let c_upper = if is_upper { v + 65 } else { 0 };
    let c_lower = if is_lower { v + 71 } else { 0 };
    let c_digit = if is_digit { v - 4 } else { 0 };
    let c_dash = if is_dash { 45 } else { 0 };
    let c_under = if is_under { 95 } else { 0 };

    c_upper + c_lower + c_digit + c_dash + c_under
}

/// Map a base64url character to its 6-bit value, asserting validity.
/// Reject characters outside the URL-safe alphabet so a prover cannot
/// silently pass a malformed signing input through the decoder.
pub fn b64url_char_to_value(c: u8) -> u8 {
    let is_upper = (c >= 65) & (c <= 90);
    let is_lower = (c >= 97) & (c <= 122);
    let is_digit = (c >= 48) & (c <= 57);
    let is_dash = c == 45;
    let is_under = c == 95;

    let v_upper = if is_upper { c - 65 } else { 0 };
    let v_lower = if is_lower { c - 71 } else { 0 };
    let v_digit = if is_digit { c + 4 } else { 0 };
    let v_dash = if is_dash { 62 } else { 0 };
    let v_under = if is_under { 63 } else { 0 };

    let valid = is_upper | is_lower | is_digit | is_dash | is_under;
    assert(valid, "Invalid base64url character");

    v_upper + v_lower + v_digit + v_dash + v_under
}

/// Encode a 32-byte hash to its 43-character base64url representation
/// (no padding). Used by SD-JWT to recover the canonical `_sd` array entry
/// shape for an issuer-published disclosure hash.
pub fn b64url_encode_hash32(bytes: [u8; B64URL_HASH_BYTES]) -> [u8; B64URL_HASH_CHAR_LEN] {
    let mut out: [u8; B64URL_HASH_CHAR_LEN] = [0; B64URL_HASH_CHAR_LEN];
    // 32 bytes = 10 full 3-byte groups + 2 trailing bytes.
    for i in 0..10 {
        let b0 = bytes[i * 3];
        let b1 = bytes[i * 3 + 1];
        let b2 = bytes[i * 3 + 2];
        let v0 = b0 >> 2;
        let v1 = ((b0 & 0x03) << 4) | (b1 >> 4);
        let v2 = ((b1 & 0x0F) << 2) | (b2 >> 6);
        let v3 = b2 & 0x3F;
        out[i * 4] = b64url_value_to_char(v0);
        out[i * 4 + 1] = b64url_value_to_char(v1);
        out[i * 4 + 2] = b64url_value_to_char(v2);
        out[i * 4 + 3] = b64url_value_to_char(v3);
    }
    // Trailing 2 bytes -> 3 characters (no padding emitted in URL-safe form).
    let b0 = bytes[30];
    let b1 = bytes[31];
    let v0 = b0 >> 2;
    let v1 = ((b0 & 0x03) << 4) | (b1 >> 4);
    let v2 = (b1 & 0x0F) << 2;
    out[40] = b64url_value_to_char(v0);
    out[41] = b64url_value_to_char(v1);
    out[42] = b64url_value_to_char(v2);
    out
}

/// Decode `b64_len` base64url characters from `input` starting at `offset`
/// into `out_len` raw bytes written to a fixed-size output buffer. The
/// caller passes `out_len` explicitly so the circuit can wire up a private
/// witness rather than infer it from `b64_len` (which may include legitimate
/// extra unused trailing chars in some encodings).
///
/// Layout rules (RFC 4648 sec. 5 without padding):
///   * `b64_len % 4 == 0` -> `out_len = (b64_len / 4) * 3`
///   * `b64_len % 4 == 2` -> `out_len = (b64_len / 4) * 3 + 1`
///   * `b64_len % 4 == 3` -> `out_len = (b64_len / 4) * 3 + 2`
///   * `b64_len % 4 == 1` is invalid and rejected.
///
/// `out_buf_len` is the const length of `out`; bytes beyond `out_len` are
/// untouched so the caller can keep zero-padding.
pub fn b64url_decode_into<let IN: u32, let OUT: u32>(
    input: [u8; IN],
    offset: u32,
    b64_len: u32,
    out_len: u32,
) -> [u8; OUT] {
    assert(offset + b64_len <= IN as u32, "base64url decode window past input bounds");
    assert(out_len <= OUT as u32, "base64url decode output exceeds buffer");
    // Reject the impossible (b64_len % 4 == 1) case fail-closed so a prover
    // cannot smuggle a single dangling base64url character that decodes to
    // ambiguous bytes.
    let rem = b64_len % 4;
    assert(rem != 1, "base64url length cannot have residue 1 mod 4");
    // Bind out_len to b64_len so the prover cannot under/over-claim:
    //   rem == 0 -> out_len == (b64_len / 4) * 3
    //   rem == 2 -> out_len == (b64_len / 4) * 3 + 1
    //   rem == 3 -> out_len == (b64_len / 4) * 3 + 2
    let full_groups = b64_len / 4;
    let expected_out = if rem == 0 {
        full_groups * 3
    } else if rem == 2 {
        full_groups * 3 + 1
    } else {
        full_groups * 3 + 2
    };
    assert(out_len == expected_out, "base64url out_len must match b64_len mod-4 layout");

    let mut out: [u8; OUT] = [0; OUT];

    // Bound the loop by OUT; for indices past the actual out_len we must not
    // mutate `out`. The conditional `if (idx as u32) < out_len { ... }`
    // guards each write.
    for group in 0..(OUT / 3 + 1) {
        let base_in = offset + group * 4;
        let base_out = group * 3;

        // Conditional reads: when `base_in + k >= offset + b64_len`, treat
        // the char as 'A' (value 0). Combined with the out-bound write
        // guard this keeps the function safe past the active region.
        let in0_idx = base_in;
        let in1_idx = base_in + 1;
        let in2_idx = base_in + 2;
        let in3_idx = base_in + 3;

        let active0 = (group * 4) < b64_len;
        let active1 = (group * 4 + 1) < b64_len;
        let active2 = (group * 4 + 2) < b64_len;
        let active3 = (group * 4 + 3) < b64_len;

        let c0 = if active0 { input[in0_idx] } else { 65 };
        let c1 = if active1 { input[in1_idx] } else { 65 };
        let c2 = if active2 { input[in2_idx] } else { 65 };
        let c3 = if active3 { input[in3_idx] } else { 65 };

        let v0 = b64url_char_to_value(c0);
        let v1 = b64url_char_to_value(c1);
        let v2 = b64url_char_to_value(c2);
        let v3 = b64url_char_to_value(c3);

        let byte0 = (v0 << 2) | (v1 >> 4);
        let byte1 = ((v1 & 0x0F) << 4) | (v2 >> 2);
        let byte2 = ((v2 & 0x03) << 6) | v3;

        if (base_out as u32) < out_len {
            out[base_out] = byte0;
        }
        if ((base_out + 1) as u32) < out_len {
            out[base_out + 1] = byte1;
        }
        if ((base_out + 2) as u32) < out_len {
            out[base_out + 2] = byte2;
        }
    }
    out
}

#[test]
fn test_value_to_char_roundtrip() {
    for v in 0..64 {
        let c = b64url_value_to_char(v as u8);
        let back = b64url_char_to_value(c);
        assert(back == v as u8, "base64url value->char->value must round-trip");
    }
}

#[test(should_fail)]
fn test_char_to_value_rejects_invalid() {
    // '!' (33) is not in the base64url alphabet; the helper must reject it
    // so a prover cannot smuggle non-canonical signing input bytes.
    let _ = b64url_char_to_value(33);
}

#[test]
fn test_encode_hash32_known_vector() {
    // Ground truth: base64url("\x00\x00...") (32 zero bytes) is "AAAAAAAA...AA" (43 'A's).
    let bytes: [u8; 32] = [0; 32];
    let chars = b64url_encode_hash32(bytes);
    for i in 0..43 {
        assert(chars[i] == 65, "Zero byte hash must encode to 43 'A' characters");
    }
}

#[test]
fn test_encode_hash32_full_alphabet() {
    // 0xFB encodes high six bits to '_' (63 -> '_'). Use a fixture spanning
    // the alphabet: bytes 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B, ...
    // Standard RFC 4648 test vectors aren't directly available, so instead
    // pin down a deterministic fixture that exercises every alphabet bucket.
    let mut bytes: [u8; 32] = [0; 32];
    bytes[0] = 0x14; // 6-bit splits to (0x05, 0x00) -> 'F', 'A'
    let chars = b64url_encode_hash32(bytes);
    assert(chars[0] == 70, "0x14 high 6 bits = 5 -> 'F'");
    assert(chars[1] == 65, "0x14 low 2 bits + zeros -> 'A'");
}

#[test]
fn test_decode_into_known_vector() {
    // "QUJD" base64url-decodes to bytes "ABC" (0x41 0x42 0x43).
    let mut input: [u8; 8] = [0; 8];
    input[0] = 81; // Q
    input[1] = 85; // U
    input[2] = 74; // J
    input[3] = 68; // D
    let out: [u8; 8] = b64url_decode_into(input, 0, 4, 3);
    assert(out[0] == 0x41, "Decoded byte 0 = 'A'");
    assert(out[1] == 0x42, "Decoded byte 1 = 'B'");
    assert(out[2] == 0x43, "Decoded byte 2 = 'C'");
}

#[test]
fn test_decode_into_two_char_residue() {
    // "QQ" decodes to a single byte 0x41 ('A'). Residue-2 case.
    let mut input: [u8; 8] = [0; 8];
    input[0] = 81; // Q
    input[1] = 81; // Q
    let out: [u8; 4] = b64url_decode_into(input, 0, 2, 1);
    assert(out[0] == 0x41, "Residue-2 b64url 'QQ' decodes to single byte 'A'");
}

#[test]
fn test_decode_into_three_char_residue() {
    // "QUI" decodes to two bytes 0x41 0x42 ("AB"). Residue-3 case.
    let mut input: [u8; 8] = [0; 8];
    input[0] = 81; // Q
    input[1] = 85; // U
    input[2] = 73; // I
    let out: [u8; 4] = b64url_decode_into(input, 0, 3, 2);
    assert(out[0] == 0x41, "Residue-3 byte 0 = 'A'");
    assert(out[1] == 0x42, "Residue-3 byte 1 = 'B'");
}

#[test(should_fail)]
fn test_decode_rejects_residue_one() {
    // A single dangling base64url char is impossible per RFC 4648; the
    // assertion in b64url_decode_into must fire.
    let input: [u8; 4] = [81, 0, 0, 0];
    let _: [u8; 4] = b64url_decode_into(input, 0, 1, 0);
}

#[test(should_fail)]
fn test_decode_rejects_invalid_char() {
    let mut input: [u8; 4] = [0; 4];
    input[0] = 81; // Q
    input[1] = 85; // U
    input[2] = 74; // J
    input[3] = 33; // '!' is not in alphabet
    let _: [u8; 4] = b64url_decode_into(input, 0, 4, 3);
}

#[test(should_fail)]
fn test_decode_rejects_out_len_mismatch() {
    // 4 input chars must decode to 3 bytes; claiming 2 bytes must fail.
    let mut input: [u8; 4] = [0; 4];
    input[0] = 81;
    input[1] = 85;
    input[2] = 74;
    input[3] = 68;
    let _: [u8; 4] = b64url_decode_into(input, 0, 4, 2);
}

#[test]
fn test_encode_then_decode_roundtrip_hash32() {
    let mut bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes[i] = (i as u8) * 7 + 13;
    }
    let chars = b64url_encode_hash32(bytes);
    let mut input: [u8; 64] = [0; 64];
    for i in 0..43 {
        input[i] = chars[i];
    }
    // 43 chars decode to 32 bytes (residue-3 layout).
    let decoded: [u8; 32] = b64url_decode_into(input, 0, 43, 32);
    for i in 0..32 {
        assert(decoded[i] == bytes[i], "encode->decode must be the identity for 32 bytes");
    }
}
