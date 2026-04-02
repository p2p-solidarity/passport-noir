// Generic predicate functions for credential attribute evaluation.
// Paper: "f_i(m_1, ..., m_n) = p_i" -- arbitrary functions over credential messages.
//
// These predicates work for ALL credential types (passport MRZ, SD-JWT claims, mDL attributes).

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

    // Adjust if birthday hasn't occurred yet this year
    if (current_month < birth_month)
        | ((current_month == birth_month) & (current_day < birth_day))
    {
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
    if yy < pivot { 2000 + yy } else { 1900 + yy }
}

// ============================================================
// Tests
// ============================================================

#[test]
fn test_age_above_18_pass() {
    // Born 2000-01-01, current 2026-04-01 -> age 26
    assert(check_age_above(2000, 1, 1, 2026, 4, 1, 18));
}

#[test]
fn test_age_above_18_fail() {
    // Born 2010-01-01, current 2026-04-01 -> age 16
    assert(!check_age_above(2010, 1, 1, 2026, 4, 1, 18));
}

#[test]
fn test_age_boundary_birthday_not_yet() {
    // Born 2008-06-15, current 2026-04-01 -> age 17 (birthday not yet)
    assert(!check_age_above(2008, 6, 15, 2026, 4, 1, 18));
}

#[test]
fn test_age_boundary_birthday_today() {
    // Born 2008-04-01, current 2026-04-01 -> age 18 exactly
    assert(check_age_above(2008, 4, 1, 2026, 4, 1, 18));
}

#[test]
fn test_bytes3_eq_match() {
    assert(check_bytes3_eq([84, 87, 78], [84, 87, 78])); // "TWN"
}

#[test]
fn test_bytes3_eq_mismatch() {
    assert(!check_bytes3_eq([84, 87, 78], [85, 83, 65])); // "TWN" != "USA"
}

#[test]
fn test_two_digit_year_2000s() {
    assert(two_digit_year_to_four(25, 50) == 2025);
}

#[test]
fn test_two_digit_year_1900s() {
    assert(two_digit_year_to_four(95, 50) == 1995);
}
