fn strstr_internal(
    haystack: &[u8],
    needle: &[u8],
    match_check_fn: impl Fn(&[u8], &[u8]) -> bool,
) -> Option<usize> {
    if haystack.is_empty() || needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    for (chunk_idx, potential_needle) in haystack.windows(needle.len()).enumerate() {
        if match_check_fn(potential_needle, needle) {
            return Some(chunk_idx);
        }
    }
    None
}

/// Returns the index of the `needle` in the `haystack` using case-insensitive comparisons, or
/// `None` if unable to find the needle.
pub fn strcasestr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    strstr_internal(haystack, needle, |a, b| {
        a.to_ascii_lowercase() == b.to_ascii_lowercase()
    })
}

/// Returns the index of the `needle` in the `haystack`, or `None` if unable to find the needle.
pub fn strstr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    strstr_internal(haystack, needle, |a, b| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strstr() {
        let haystack = "thisisMYSTRINGabc";
        assert_eq!(
            6,
            strstr(haystack.as_bytes(), "MYSTRING".as_bytes()).unwrap()
        );
        assert!(strstr(haystack.as_bytes(), "mystring".as_bytes()).is_none());
    }

    #[test]
    fn test_strcasestr() {
        let haystack = "thisisMYSTRINGabc";
        assert_eq!(
            haystack.find("MYSTRING").unwrap(),
            strcasestr(haystack.as_bytes(), "MYSTRING".as_bytes()).unwrap()
        );
        assert_eq!(
            haystack.find("MYSTRING").unwrap(),
            strcasestr(haystack.as_bytes(), "mystring".as_bytes()).unwrap()
        );
        assert_eq!(2, strcasestr(haystack.as_bytes(), "is".as_bytes()).unwrap());
        assert!(strcasestr(haystack.as_bytes(), "LAC".as_bytes()).is_none());

        let empty = "";
        assert!(strcasestr("".as_bytes(), "".as_bytes()).is_none());
    }
}
