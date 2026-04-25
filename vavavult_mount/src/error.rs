/// vavavult_mount 统一错误类型。
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// Vault 操作相关错误 (查询、提取、添加等)。
    #[error("Vault operation error: {0}")]
    VaultError(String),

    /// IO 错误 (网络绑定、文件操作等)。
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP/WebDAV 服务器错误。
    #[error("Server error: {0}")]
    ServerError(String),

    /// 认证相关错误。
    #[error("Authentication error: {0}")]
    AuthError(String),

    /// 配置无效。
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
