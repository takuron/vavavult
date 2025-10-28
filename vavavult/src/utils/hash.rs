use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
/// 将哈希字节（例如 SHA256 的 32 字节）编码为
/// 长度固定 (43 字节)、无填充、且 URL 安全的 Base64 字符串。
///
/// 这种格式替换 `+` 为 `_` (标准 URL Safe)，并替换 `/` 为 `-` (您的自定义要求)。
///
/// # Arguments
/// * `hash_bytes` - 原始的哈希字节数组 (例如 `[u8; 32]`)。
///
/// # Returns
/// 一个 43 字符长的 Base64 字符串。
pub fn encode_hash_to_base64(hash_bytes: &[u8]) -> String {
    // 1. 使用标准 "无填充" 引擎进行编码
    let mut s = STANDARD_NO_PAD.encode(hash_bytes);

    // 2. 根据您的要求，手动替换 `/` 为 `-`
    // (注意：标准 URL safe 也会替换 `+` 为 `_`，但您的要求是 `/` -> `-`。
    //  为了安全起见，我们同时替换两者以符合 `base64::URL_SAFE_NO_PAD` 的行为，
    //  同时确保 `/` 被替换为您指定的 `-`。)
    s = s.replace('/', "-").replace('+', "_");

    // 确保32字节的哈希总是43个字符
    assert_eq!(s.len(), 43, "SHA256 Base64 (unpadded) 编码应为 43 字节");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_base64_encoding() {
        // 一个 SHA256 结果 (32 字节)
        let sha256_bytes: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xA2, 0x22, 0x3B,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        let encoded = encode_hash_to_base64(&sha256_bytes);
        println!("Encoded: {}", encoded);

        // 验证长度
        assert_eq!(encoded.len(), 43);
        // 验证没有填充
        assert!(!encoded.contains('='));
        // 验证没有 `/`
        assert!(!encoded.contains('/'));
        // 验证没有 `+`
        assert!(!encoded.contains('+'));
    }
}