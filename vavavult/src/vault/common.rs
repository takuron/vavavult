/// 将路径字符串规范化为保险库内部的绝对路径格式。
///
/// 例如:
/// - "a/b.txt" -> "/a/b.txt"
/// - "/a/b.txt" -> "/a/b.txt"
/// - "file.txt" -> "/file.txt"
/// - "a//b/" -> "/a/b"
pub(crate) fn normalize_path_name(name: &str) -> String {
    let parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    format!("/{}", parts.join("/"))
}