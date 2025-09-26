/// Normalizes a path string into the vault's absolute path format.
///
/// This ensures a consistent, root-based path structure within the vault.
///
/// Examples:
/// - "a/b.txt" -> "/a/b.txt"
/// - "/a/b.txt" -> "/a/b.txt"
/// - "file.txt" -> "/file.txt"
/// - "a//b/" -> "/a/b"
/// - "a\\b.txt" -> "/a/b.txt"  // Handles Windows paths
pub fn normalize_path_name(name: &str) -> String {
    // 新增：将所有反斜杠替换为正斜杠，以兼容 Windows 路径
    let name_with_forward_slashes = name.replace('\\', "/");
    let parts: Vec<&str> = name_with_forward_slashes.split('/').filter(|s| !s.is_empty()).collect();
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
        // 新增：测试 Windows 路径
        assert_eq!(normalize_path_name("a\\b.txt"), "/a/b.txt");
        assert_eq!(normalize_path_name("a\\b\\"), "/a/b");
        assert_eq!(normalize_path_name("C:\\Users\\Test\\file.txt"), "/C:/Users/Test/file.txt");
    }
}