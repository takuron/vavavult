/// HTTP Basic Auth validation utilities.
///
/// Provides a stateless function to validate HTTP Basic Auth credentials
/// against an expected `AuthConfig`. Used by the WebDAV server to gate
/// access when authentication is configured.
//
// // HTTP Basic Auth 验证工具。
// //
// // 提供一个无状态函数，用于根据预期的 `AuthConfig` 验证 HTTP Basic Auth 凭据。
// // 当配置了认证时，WebDAV 服务器使用此函数来控制访问。
use crate::config::AuthConfig;

/// Validates an HTTP Basic Auth header value against the expected credentials.
///
/// # Arguments
/// * `auth_header` - The raw value of the `Authorization` header (e.g. `"Basic dXNlcjpwYXNz"`),
///   or `None` if the header is absent.
/// * `expected` - The expected username and password.
///
/// # Returns
/// `true` if the header is present, correctly formatted, and the decoded
/// credentials match `expected`. `false` in all other cases.
//
// // 根据预期凭据验证 HTTP Basic Auth 头值。
// //
// // # 参数
// // * `auth_header` - `Authorization` 头的原始值（例如 `"Basic dXNlcjpwYXNz"`），
// //   如果头不存在则为 `None`。
// // * `expected` - 预期的用户名和密码。
// //
// // # 返回
// // 如果头存在、格式正确且解码后的凭据与 `expected` 匹配，则返回 `true`。
// // 其他所有情况返回 `false`。
pub fn check_basic_auth(auth_header: Option<&str>, expected: &AuthConfig) -> bool {
    let header_value = match auth_header {
        Some(v) => v,
        None => return false,
    };

    // 1. 去掉 "Basic " 前缀
    let encoded = match header_value.strip_prefix("Basic ") {
        Some(e) => e,
        None => return false,
    };

    // 2. Base64 解码
    use base64::Engine as _;
    let decoded_bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let decoded_str = match String::from_utf8(decoded_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 3. 按 "username:password" 格式拆分并比较
    match decoded_str.split_once(':') {
        Some((user, pass)) => user == expected.username && pass == expected.password,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth(username: &str, password: &str) -> AuthConfig {
        AuthConfig {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn encode_basic(username: &str, password: &str) -> String {
        use base64::Engine as _;
        let raw = format!("{}:{}", username, password);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }

    #[test]
    fn test_valid_credentials() {
        let auth = make_auth("alice", "secret");
        let header = encode_basic("alice", "secret");
        assert!(check_basic_auth(Some(&header), &auth));
    }

    #[test]
    fn test_wrong_password() {
        let auth = make_auth("alice", "secret");
        let header = encode_basic("alice", "wrong");
        assert!(!check_basic_auth(Some(&header), &auth));
    }

    #[test]
    fn test_wrong_username() {
        let auth = make_auth("alice", "secret");
        let header = encode_basic("bob", "secret");
        assert!(!check_basic_auth(Some(&header), &auth));
    }

    #[test]
    fn test_missing_header() {
        let auth = make_auth("alice", "secret");
        assert!(!check_basic_auth(None, &auth));
    }

    #[test]
    fn test_no_basic_prefix() {
        let auth = make_auth("alice", "secret");
        assert!(!check_basic_auth(Some("Bearer token123"), &auth));
    }

    #[test]
    fn test_invalid_base64() {
        let auth = make_auth("alice", "secret");
        assert!(!check_basic_auth(Some("Basic !!!invalid!!!"), &auth));
    }

    #[test]
    fn test_no_colon_separator() {
        use base64::Engine as _;
        let auth = make_auth("alice", "secret");
        let encoded = base64::engine::general_purpose::STANDARD.encode("alicesecret");
        let header = format!("Basic {}", encoded);
        assert!(!check_basic_auth(Some(&header), &auth));
    }

    #[test]
    fn test_password_with_colon() {
        // 密码中包含冒号时，只在第一个冒号处分割
        let auth = make_auth("alice", "pass:word");
        let header = encode_basic("alice", "pass:word");
        assert!(check_basic_auth(Some(&header), &auth));
    }
}
