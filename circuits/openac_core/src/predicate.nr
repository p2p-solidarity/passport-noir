// Generic predicate functions for credential attribute evaluation.
// Paper: "f_i(m_1, ..., m_n) = p_i" -- arbitrary functions over credential messages.
//
// These predicates work for ALL credential types (passport MRZ, SD-JWT claims, mDL attributes).

use std::hash::pedersen_hash;

use crate::profile::unpack_passport_claims;

/// Check if age is above a threshold given a birth date and current date.
/// Handles century rollover for 2-digit year formats (e.g., MRZ uses YY format).
///
/// Paper: f_i(m) in {0,1} (range check / boolean predicate)
pub fn check_age_above(
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    current_year: u32,
    current_month: u32,
    current_day: u32,
    threshold: u32,
) -> bool {
    assert(current_year >= birth_year, "Birth year cannot be after current year");
    let mut age = current_year - birth_year;

    // Adjust if birthday hasn't occurred yet this year.
    // Security (HIGH-2, 2026-06-10): `age` is u32, so `age -= 1` would WRAP to
    // ~4.29e9 when age == 0 (birth_year == current_year, birthday in the future).
    // That wrapped value trivially satisfies `age >= threshold`, letting a
    // same-year newborn forge an "over 18" proof. Only subtract when age > 0;
    // an effectively-negative age stays at 0, which is below any positive
    // threshold, so the predicate correctly returns false.
    let birthday_not_yet = (current_month < birth_month)
        | ((current_month == birth_month) & (current_day < birth_day));
    if birthday_not_yet & (age > 0) {
        age -= 1;
    }

    age >= threshold
}

/// Check if a 3-byte field (e.g., nationality code) equals an expected value.
/// Paper: f_i(m) = m_i (direct disclosure / equality check)
pub fn check_bytes3_eq(actual: [u8; 3], expected: [u8; 3]) -> bool {
    (actual[0] == expected[0]) & (actual[1] == expected[1]) & (actual[2] == expected[2])
}

/// Convert a 2-digit year to 4-digit year with century rollover.
/// MRZ format uses YY; this converts using a pivot (e.g., 50):
///   00-49 -> 2000-2049
///   50-99 -> 1950-1999
pub fn two_digit_year_to_four(yy: u32, pivot: u32) -> u32 {
    if yy < pivot {
        2000 + yy
    } else {
        1900 + yy
    }
}

fn zero_terminated_len_31(value: [u8; 31]) -> u32 {
    let mut len: u32 = 31;
    let mut seen_zero = false;

    for i in 0..31 {
        if !seen_zero & (value[i] == 0) {
            len = i as u32;
            seen_zero = true;
        }
    }

    len
}

fn zero_terminated_len_64(value: [u8; 64]) -> u32 {
    let mut len: u32 = 64;
    let mut seen_zero = false;

    for i in 0..64 {
        if !seen_zero & (value[i] == 0) {
            len = i as u32;
            seen_zero = true;
        }
    }

    len
}

/// Decode a packed attribute pair into a single Field via domain-free
/// pedersen_hash. Shared by x509_show and composite_show so that verifier-side
/// `target_*_hash` commitments use one canonical transform across Path A
/// circuits. Spec: x509-circuits.md sec 6, 7, 10.
pub fn decode_domain(attr_hi: Field, attr_lo: Field) -> Field {
    pedersen_hash([attr_hi, attr_lo])
}

/// Evaluate "packed passport claims encode a birth date at least `threshold`
/// years before (current_year, current_month, current_day)". Returns Field 0/1
/// so the result can be published directly as `out_is_older`. v3.1: takes the
/// single packed claims Field from `profile::pack_passport_claims` (was an
/// (attr_hi, attr_lo) pair in v3).
pub fn age_from_claims(
    claims: Field,
    current_year: u32,
    current_month: u32,
    current_day: u32,
    threshold: u32,
) -> Field {
    let (birth_year, birth_month, birth_day, _nationality) = unpack_passport_claims(claims);
    if check_age_above(
        birth_year,
        birth_month,
        birth_day,
        current_year,
        current_month,
        current_day,
        threshold,
    ) {
        1
    } else {
        0
    }
}

/// Evaluate "opened aux attrs pedersen-hash to the verifier-supplied target".
/// Used uniformly by composite_show for both X.509 domain-match and SD-JWT
/// sd_root equality checks -- the spec overloads `target_domain_hash` as
/// "expected opened attr hash" regardless of credential type (x509-circuits.md
/// sec 7). Returns Field 0/1 for direct output publication.
pub fn sdjwt_predicate_check(attr_hi: Field, attr_lo: Field, target_hash: Field) -> Field {
    if decode_domain(attr_hi, attr_lo) == target_hash {
        1
    } else {
        0
    }
}

pub fn domain_suffix_match(actual: [u8; 31], expected_suffix: [u8; 64]) -> bool {
    let actual_len = zero_terminated_len_31(actual);
    let suffix_len = zero_terminated_len_64(expected_suffix);
    let mut matches = (suffix_len > 0) & (suffix_len <= actual_len);
    let offset = actual_len - suffix_len;

    for i in 0..64 {
        if ((i as u32) < suffix_len) & matches {
            if actual[offset + i as u32] != expected_suffix[i] {
                matches = false;
            }
        }
    }

    matches
}

// ============================================================
// Tests
// ============================================================

#[test]
fn test_age_above_18_pass() {
    // Born 2000-01-01, current 2026-04-01 -> age 26
    assert(check_age_above(2000, 1, 1, 2026, 4, 1, 18), "Age 26 should pass threshold 18");
}

#[test]
fn test_age_above_18_fail() {
    // Born 2010-01-01, current 2026-04-01 -> age 16
    assert(!check_age_above(2010, 1, 1, 2026, 4, 1, 18), "Age 16 should not pass threshold 18");
}

#[test]
fn test_age_boundary_birthday_not_yet() {
    // Born 2008-06-15, current 2026-04-01 -> age 17 (birthday not yet)
    assert(
        !check_age_above(2008, 6, 15, 2026, 4, 1, 18),
        "Birthday not yet should reduce age by 1",
    );
}

#[test]
fn test_age_boundary_birthday_today() {
    // Born 2008-04-01, current 2026-04-01 -> age 18 exactly
    assert(check_age_above(2008, 4, 1, 2026, 4, 1, 18), "Birthday today should count as full age");
}

#[test(should_fail)]
fn test_age_fails_on_future_birth_year() {
    // Birth year after current year should assert-fail
    let _ = check_age_above(2030, 1, 1, 2026, 4, 1, 18);
}

#[test]
fn test_age_zero_threshold() {
    // Age 26 >= 0 should always pass
    assert(check_age_above(2000, 1, 1, 2026, 4, 1, 0), "Zero threshold should always pass");
}

#[test]
fn test_bytes3_eq_match() {
    assert(check_bytes3_eq([84, 87, 78], [84, 87, 78]), "TWN should equal TWN");
}

#[test]
fn test_bytes3_eq_mismatch() {
    assert(!check_bytes3_eq([84, 87, 78], [85, 83, 65]), "TWN should not equal USA");
}

#[test]
fn test_bytes3_eq_single_byte_diff() {
    assert(!check_bytes3_eq([84, 87, 78], [84, 87, 79]), "Single byte difference should fail");
}

#[test]
fn test_two_digit_year_2000s() {
    assert(two_digit_year_to_four(25, 50) == 2025, "YY=25 with pivot 50 should be 2025");
}

#[test]
fn test_two_digit_year_1900s() {
    assert(two_digit_year_to_four(95, 50) == 1995, "YY=95 with pivot 50 should be 1995");
}

#[test]
fn test_two_digit_year_at_pivot() {
    assert(two_digit_year_to_four(50, 50) == 1950, "YY=50 at pivot should be 1950");
}

#[test]
fn test_two_digit_year_below_pivot() {
    assert(two_digit_year_to_four(49, 50) == 2049, "YY=49 below pivot should be 2049");
}

#[test]
fn test_domain_suffix_match_exact_domain() {
    let actual: [u8; 31] = [
        110, 116, 117, 46, 101, 100, 117, 46, 116, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let mut expected: [u8; 64] = [0; 64];
    expected[0] = 110;
    expected[1] = 116;
    expected[2] = 117;
    expected[3] = 46;
    expected[4] = 101;
    expected[5] = 100;
    expected[6] = 117;
    expected[7] = 46;
    expected[8] = 116;
    expected[9] = 119;
    assert(domain_suffix_match(actual, expected), "Exact domain match should succeed");
}

#[test]
fn test_domain_suffix_match_subdomain() {
    let actual: [u8; 31] = [
        99, 115, 105, 101, 46, 110, 116, 117, 46, 101, 100, 117, 46, 116, 119, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut expected: [u8; 64] = [0; 64];
    expected[0] = 110;
    expected[1] = 116;
    expected[2] = 117;
    expected[3] = 46;
    expected[4] = 101;
    expected[5] = 100;
    expected[6] = 117;
    expected[7] = 46;
    expected[8] = 116;
    expected[9] = 119;
    assert(domain_suffix_match(actual, expected), "Suffix match should succeed for subdomains");
}

#[test]
fn test_domain_suffix_match_rejects_mismatch() {
    let actual: [u8; 31] = [
        99, 115, 105, 101, 46, 110, 116, 117, 46, 101, 100, 117, 46, 116, 119, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut expected: [u8; 64] = [0; 64];
    expected[0] = 103;
    expected[1] = 111;
    expected[2] = 111;
    expected[3] = 103;
    expected[4] = 108;
    expected[5] = 101;
    expected[6] = 46;
    expected[7] = 99;
    expected[8] = 111;
    expected[9] = 109;
    assert(!domain_suffix_match(actual, expected), "Mismatched domain suffix should fail");
}

#[test]
fn test_decode_domain_deterministic() {
    let a = decode_domain(123, 456);
    let b = decode_domain(123, 456);
    assert(a == b, "decode_domain must be deterministic for identical inputs");
}

#[test]
fn test_decode_domain_differs_on_input() {
    let a = decode_domain(123, 456);
    let b = decode_domain(123, 457);
    assert(a != b, "decode_domain must differentiate distinct attr_lo values");
}

#[test]
fn test_age_from_claims_pass() {
    let claims = crate::profile::pack_passport_claims(2000, 1, 1, [84, 87, 78]);
    let out = age_from_claims(claims, 2026, 4, 1, 18);
    assert(out == 1, "Age 26 should satisfy threshold 18");
}

#[test]
fn test_age_from_claims_fail() {
    let claims = crate::profile::pack_passport_claims(2010, 1, 1, [84, 87, 78]);
    let out = age_from_claims(claims, 2026, 4, 1, 18);
    assert(out == 0, "Age 16 should not satisfy threshold 18");
}

#[test]
fn test_sdjwt_predicate_check_match() {
    let attr_hi: Field = 0xABCDEF;
    let attr_lo: Field = 0x123456;
    let target = decode_domain(attr_hi, attr_lo);
    assert(sdjwt_predicate_check(attr_hi, attr_lo, target) == 1, "Matching hash should return 1");
}

#[test]
fn test_sdjwt_predicate_check_mismatch() {
    let attr_hi: Field = 0xABCDEF;
    let attr_lo: Field = 0x123456;
    let wrong_target: Field = 0xDEADBEEF;
    assert(
        sdjwt_predicate_check(attr_hi, attr_lo, wrong_target) == 0,
        "Non-matching hash should return 0",
    );
}

// Security regression (HIGH-2, 2026-06-10): a holder born this calendar year
// whose birthday has not yet arrived must NOT pass any positive age threshold.
// Before the underflow guard, `age -= 1` wrapped u32 0 to ~4.29e9, which
// satisfied every threshold.
#[test]
fn test_age_same_year_future_birthday_no_underflow() {
    // Born 2026-06-15, "today" 2026-03-01: age is effectively -1, must be < 18.
    assert(
        !check_age_above(2026, 6, 15, 2026, 3, 1, 18),
        "Same-year future birthday must not satisfy threshold 18",
    );
    // Must also fail even threshold 1 (genuinely zero years old, not 4 billion).
    assert(
        !check_age_above(2026, 6, 15, 2026, 3, 1, 1),
        "Same-year future birthday must not satisfy threshold 1",
    );
}

#[test]
fn test_age_same_year_birthday_passed() {
    // Born 2026-01-10, "today" 2026-06-01: 0 years old, passes threshold 0 only.
    assert(check_age_above(2026, 1, 10, 2026, 6, 1, 0), "0yo satisfies threshold 0");
    assert(!check_age_above(2026, 1, 10, 2026, 6, 1, 1), "0yo must not satisfy threshold 1");
}
