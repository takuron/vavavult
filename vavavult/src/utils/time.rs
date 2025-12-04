use chrono::{DateTime, ParseError, Utc};

/// Returns the current UTC time as a string formatted according to RFC 3339.
///
/// This format is chosen for its unambiguity and widespread support.
/// Example: "2025-09-13T03:49:58.123456789Z"
pub fn now_as_rfc3339_string() -> String {
    Utc::now().to_rfc3339()
}

/// Parses an RFC 3339 formatted string back into a `DateTime<Utc>` object.
///
/// # Arguments
/// * `s` - A string slice representing a timestamp in RFC 3339 format.
///
/// # Errors
/// Returns a `ParseError` if the string is not a valid RFC 3339 timestamp.
pub fn _parse_rfc3339_string(s: &str) -> Result<DateTime<Utc>, ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_conversion_roundtrip() {
        // 1. Get the current time as a string
        let now_string = now_as_rfc3339_string();
        println!("Generated timestamp string: {}", now_string);

        // 2. Parse it back to a DateTime object
        let parsed_datetime =
            _parse_rfc3339_string(&now_string).expect("Should parse successfully");
        println!("Parsed back to DateTime: {:?}", parsed_datetime);

        // 3. Convert the parsed object back to a string
        let roundtrip_string = parsed_datetime.to_rfc3339();

        // 4. Assert that the original and round-tripped strings are identical
        assert_eq!(now_string, roundtrip_string);
    }

    #[test]
    fn test_parse_invalid_string() {
        let invalid_string = "not-a-timestamp";
        let result = _parse_rfc3339_string(invalid_string);
        assert!(result.is_err());
    }
}