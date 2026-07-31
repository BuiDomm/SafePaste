use std::collections::HashSet;

pub(crate) fn validate(name: Option<&str>, value: &str, min_entropy: Option<f64>) -> bool {
    let valid = match name.unwrap_or("none") {
        "none" => true,
        "luhn" => luhn(value),
        "iban" => iban(value),
        "ipv4" => ipv4(value),
        "vn_cccd" => vn_cccd(value),
        "vn_tax_id" => vn_tax_id(value),
        "entropy" => true,
        _ => false,
    };

    valid && min_entropy.is_none_or(|minimum| shannon_entropy(value) >= minimum)
}

fn digits(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

pub(crate) fn luhn(value: &str) -> bool {
    let digits = digits(value);
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    // A 13-digit value beginning with 1 is overwhelmingly likely to be a
    // Unix millisecond timestamp, a frequent hard negative in logs.
    if digits.len() == 13 && digits.starts_with('1') {
        return false;
    }

    let mut sum = 0u32;
    let parity = digits.len() % 2;
    for (index, byte) in digits.bytes().enumerate() {
        let mut digit = u32::from(byte - b'0');
        if index % 2 == parity {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum.is_multiple_of(10)
}

pub(crate) fn iban(value: &str) -> bool {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if !(15..=34).contains(&compact.len()) || !compact.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut remainder = 0u32;
    for character in rearranged.chars() {
        if character.is_ascii_digit() {
            remainder = (remainder * 10 + character.to_digit(10).unwrap_or_default()) % 97;
        } else {
            let value = u32::from(character as u8 - b'A') + 10;
            remainder = (remainder * 100 + value) % 97;
        }
    }
    remainder == 1
}

pub(crate) fn ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part == &"0" || !part.starts_with('0'))
                && part.parse::<u8>().is_ok()
        })
}

pub(crate) fn vn_cccd(value: &str) -> bool {
    let digits = digits(value);
    if digits.len() != 12 {
        return false;
    }

    let province_codes: HashSet<&'static str> = [
        "001", "002", "004", "006", "008", "010", "011", "012", "014", "015", "017", "019", "020",
        "022", "024", "025", "026", "027", "030", "031", "033", "034", "035", "036", "037", "038",
        "040", "042", "044", "045", "046", "048", "049", "051", "052", "054", "056", "058", "060",
        "062", "064", "066", "067", "068", "070", "072", "074", "075", "077", "079", "080", "082",
        "083", "084", "086", "087", "089", "091", "092", "093", "094", "095", "096",
    ]
    .into_iter()
    .collect();

    province_codes.contains(&digits[..3])
        && digits.as_bytes()[3].is_ascii_digit()
        && digits[4..6].parse::<u8>().is_ok_and(|year| year <= 99)
}

pub(crate) fn vn_tax_id(value: &str) -> bool {
    let root = value.split('-').next().unwrap_or(value);
    if root.len() != 10 || !root.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let weights = [31u32, 29, 23, 19, 17, 13, 7, 5, 3];
    let bytes = root.as_bytes();
    let sum: u32 = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| u32::from(bytes[index] - b'0') * weight)
        .sum();
    let expected = 10 - (sum % 11);
    let expected = if expected == 10 { 0 } else { expected };
    expected < 10 && expected == u32::from(bytes[9] - b'0')
}

pub(crate) fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in value.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let length = value.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_luhn_numbers() {
        assert!(luhn("4242 4242 4242 4242"));
        assert!(!luhn("4242 4242 4242 4241"));
    }

    #[test]
    fn validates_iban_modulo() {
        assert!(iban("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban("GB82 WEST 1234 5698 7654 31"));
    }

    #[test]
    fn validates_ipv4_boundaries() {
        assert!(ipv4("192.168.1.1"));
        assert!(!ipv4("999.168.1.1"));
    }
}
