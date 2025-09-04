/// 将路径字符串规范化为保险库内部的绝对路径格式。
///
/// 例如:
/// - "a/b.txt" -> "/a/b.txt"
/// - "/a/b.txt" -> "/a/b.txt"
/// - "file.txt" -> "/file.txt"
/// - "a//b/" -> "/a/b"
pub fn normalize_path_name(name: &str) -> String {
    let parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    format!("/{}", parts.join("/"))
}

/// 生成一个包含字母、数字和特殊字符的指定长度的随机密码。
///
/// # Arguments
/// * `length` - 密码的期望长度。
pub fn generate_random_password(length: usize) -> String {
    // 1. 定义密码字符集
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789\
                            !@#$%^&*()_+-=[]{}|;:,.<>?";

    // 2. 生成所需长度的加密安全随机字节
    let mut random_bytes = vec![0u8; length];
    openssl::rand::rand_bytes(&mut random_bytes).unwrap();

    // 3. 将每个随机字节映射到字符集中的一个字符
    let password: String = random_bytes.iter().map(|&byte| {
        let char_index = byte as usize % CHARSET.len();
        CHARSET[char_index] as char
    }).collect();

    password
}