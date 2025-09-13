/// Generates a random password of a specified length, including letters, numbers, and special characters.
pub fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789\
                            !@#$%^&*()_+-=[]{}|;:,.<>?";
    generate_random_from_charset(length, CHARSET)
}

/// Generates a random alphanumeric string of a specified length.
pub fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    generate_random_from_charset(length, CHARSET)
}

/// A helper function to generate a random string from a given charset.
fn generate_random_from_charset(length: usize, charset: &[u8]) -> String {
    if charset.is_empty() {
        return String::new();
    }
    let mut random_bytes = vec![0u8; length];
    openssl::rand::rand_bytes(&mut random_bytes).unwrap();

    random_bytes
        .iter()
        .map(|&byte| {
            let char_index = byte as usize % charset.len();
            charset[char_index] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_password() {
        let password = generate_random_password(16);
        assert_eq!(password.len(), 16);
        // Simple check to ensure it's not empty and has the correct length
        assert!(!password.is_empty());
    }

    #[test]
    fn test_generate_random_string() {
        let s = generate_random_string(24);
        assert_eq!(s.len(), 24);
        assert!(!s.is_empty());
        // Ensure it only contains alphanumeric characters
        assert!(s.chars().all(|c| c.is_alphanumeric()));
    }
}