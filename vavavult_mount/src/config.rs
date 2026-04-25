/// HTTP Basic Auth 凭据。
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

/// WebDAV 挂载服务的配置。
#[derive(Clone, Debug)]
pub struct MountConfig {
    /// 监听地址，默认 "127.0.0.1"（仅本机访问）。
    /// 设为 "0.0.0.0" 可允许局域网访问。
    pub bind_address: String,

    /// 监听端口，默认 8080。
    pub port: u16,

    /// 是否为只读模式。默认 true，安全优先。
    /// 为 true 时，PUT / DELETE / MOVE 等写入操作返回 403。
    pub read_only: bool,

    /// 可选的 HTTP Basic Auth 配置。
    /// 为 None 时不需要认证（仅建议本机使用）。
    pub auth: Option<AuthConfig>,

    /// WebDAV URL 路径前缀，默认 "/"。
    pub prefix: String,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            read_only: true,
            auth: None,
            prefix: "/".to_string(),
        }
    }
}
