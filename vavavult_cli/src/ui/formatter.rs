//! UI-related string formatting, like colorization.

/// 使用 ANSI 代码为字符串着色
pub fn colorize_string(s: &str, color: &str) -> String {
    let code = match color {
        "red" => "[31m",
        "green" => "[32m",
        "yellow" => "[33m",
        "blue" => "[34m",
        "magenta" => "[35m",
        "cyan" => "[36m",
        _ => return s.to_string(), // 未知颜色或无颜色
    };
    format!("{}{}\x1b[0m", code, s)
}

/// 从标签列表中提取颜色 (例如 "_color:red" -> "red")
pub fn get_file_color(tags: &[String]) -> Option<&str> {
    for tag in tags {
        if let Some(color_val) = tag.strip_prefix("_color:") {
            return Some(color_val);
        }
    }
    None
}
