/// Normalizes a path string into the vault's absolute path format.
///
/// This ensures a consistent, root-based path structure within the vault.
///
/// Examples:
/// - "a/b.txt" -> "/a/b.txt"
/// - "/a/b.txt" -> "/a/b.txt"
/// - "file.txt" -> "/file.txt"
/// - "a//b/" -> "/a/b"
pub fn normalize_path_name(name: &str) -> String {
    let parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_name() {
        assert_eq!(normalize_path_name("a/b.txt"), "/a/b.txt");
        assert_eq!(normalize_path_name("/a/b.txt"), "/a/b.txt");
        assert_eq!(normalize_path_name("file.txt"), "/file.txt");
        assert_eq!(normalize_path_name("a//b/"), "/a/b");
        assert_eq!(normalize_path_name("/"), "/");
        assert_eq!(normalize_path_name(""), "/");
    }
}