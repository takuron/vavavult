use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use rusqlite::Connection;
use serde_json::Value;
use crate::common::constants::CURRENT_VAULT_VERSION;
use crate::crypto::encrypt::verify_v2_encrypt_check;
use crate::storage::StorageBackend;
use crate::vault::{Vault, VaultConfig};

/// Defines errors that can occur when opening an existing vault.
//
// // 定义在打开一个已存在的保险库时可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The specified path does not exist or is not a directory.
    //
    // // 指定的路径不存在或不是一个目录。
    #[error("Vault path does not exist or is not a directory: {0}")]
    PathNotFound(PathBuf),

    /// The `master.json` file is missing from the vault directory.
    //
    // // 保险库目录中缺少 `master.json` 文件。
    #[error("Configuration file 'master.json' not found in vault.")]
    ConfigNotFound,

    /// The database file (e.g., `master.db`) specified in the config is missing.
    //
    // // 配置中指定的数据库文件 (例如 `master.db`) 丢失。
    #[error("Database file specified in config not found.")]
    DatabaseNotFound,

    /// An I/O error occurred while reading the configuration file.
    //
    // // 读取配置文件时发生 I/O 错误。
    #[error("Failed to read configuration file: {0}")]
    ConfigReadError(#[from] std::io::Error),

    /// Failed to parse the `master.json` configuration file.
    //
    // // 解析 `master.json` 配置文件失败。
    #[error("Failed to parse configuration file: {0}")]
    ConfigParseError(#[from] serde_json::Error),

    /// Failed to open or connect to the SQLite database.
    //
    // // 打开或连接到 SQLite 数据库失败。
    #[error("Failed to open database: {0}")]
    DatabaseOpenError(#[from] rusqlite::Error),

    /// An incorrect password was provided for an encrypted vault.
    //
    // // 为加密保险库提供了错误的密码。
    #[error("Invalid password provided for encrypted vault.")]
    InvalidPassword,

    /// The vault is encrypted, but no password was provided.
    //
    // // 保险库已加密，但未提供密码。
    #[error("Password required for an encrypted vault but was not provided.")]
    PasswordRequired,

    /// The vault's version in `master.json` is not supported by this library version.
    //
    // // `master.json` 中的保险库版本不受此库版本支持。
    #[error("Unsupported vault version: found {found}, but this library supports version {supported}.")]
    UnsupportedVersion {
        supported: u32,
        found: u32,
    },
}

/// 打开一个已存在的保险库。
pub fn open_vault(
    vault_path: &Path,
    password: Option<&str>,
    backend: Arc<dyn StorageBackend>
) -> Result<Vault, OpenError> {
    if !vault_path.is_dir() {
        return Err(OpenError::PathNotFound(vault_path.to_path_buf()));
    }

    let config_path = vault_path.join("master.json");
    if !config_path.exists() {
        return Err(OpenError::ConfigNotFound);
    }

    let config_content = fs::read_to_string(config_path)?;

    // --- 版本检查 ---
    let config_value: Value = serde_json::from_str(&config_content)?;
    let version = config_value["version"].as_u64().unwrap_or(0) as u32;

    if version != CURRENT_VAULT_VERSION {
        return Err(OpenError::UnsupportedVersion {
            supported: CURRENT_VAULT_VERSION,
            found: version,
        });
    }

    let config: VaultConfig = serde_json::from_str(&config_content)?;

    let db_path = vault_path.join(&config.database);
    if !db_path.exists() {
        return Err(OpenError::DatabaseNotFound);
    }
    let conn = Connection::open(db_path)?;

    if config.encrypted {
        match password {
            Some(p) => {
                if !verify_v2_encrypt_check(&config.encrypt_check, p) {
                    return Err(OpenError::InvalidPassword);
                }

                conn.pragma_update(None, "key", p)?;

                let verification_query = conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |row| row.get::<_, i64>(0),
                );
                if verification_query.is_err() {
                    return Err(OpenError::InvalidPassword);
                }
            }
            None => {
                return Err(OpenError::PasswordRequired);
            }
        }
    }

    Ok(Vault {
        root_path: vault_path.to_path_buf(),
        config,
        database_connection: conn,
        storage: backend,
    })
}