use std::fs;
use std::path::{Path, PathBuf};
use rusqlite::{Connection};
use crate::file::encrypt::{EncryptError, EncryptionCheck, EncryptionType};
use crate::vault::config::VaultConfig;
use crate::vault::create::CreateError::VaultAlreadyExists;
use crate::vault::Vault;

#[derive(Debug, thiserror::Error)] // 使用 thiserror 库来简化错误类型的创建
pub enum CreateError {
    #[error("Vault directory already exists at {0}")]
    VaultAlreadyExists(PathBuf),

    #[error("Failed to create vault directory: {0}")]
    DirectoryCreationError(#[from] std::io::Error), // 可以从 std::io::Error 自动转换

    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error), // 可以从 serde_json::Error 自动转换

    #[error("Failed to init database: {0}")]
    DatabaseInitError(#[from] rusqlite::Error), // 可以从 serde_json::Error 自动转换

    // [新增] 添加一个新的错误类型，用于处理加密相关的错误
    #[error("Failed to create encryption check: {0}")]
    EncryptionError(#[from] EncryptError),
}

/// 创建一个新的保险库。
///
/// # Arguments
/// * `vault_path` - 保险库的根目录路径。
/// * `vault_name` - 保险库的名称。
/// * `password` - (可选) 如果提供了密码，将创建一个加密的保险库。
///
/// # Returns
/// 成功时返回一个 `Vault` 实例，否则返回 `CreateError`。
pub fn create_vault(vault_path: &Path, vault_name: &str, password: Option<&str>) -> Result<Vault, CreateError>{
    if vault_path.exists() && fs::read_dir(vault_path)?.next().is_some(){
        return  Err(VaultAlreadyExists(vault_path.to_path_buf()));
    } else {
        fs::create_dir_all(vault_path)?;
    }

    let (encrypt_type, encrypt_check) = if let Some(p) = password {
        (EncryptionType::Aes256Gcm, EncryptionCheck::new(p)?)
    } else {
        (EncryptionType::None, EncryptionCheck {
            raw: "".to_string(),
            encrypted: "".to_string(),
        })
    };

    let new_config = VaultConfig {
        name: vault_name.to_string(),
        version: 1,
        encrypt_type: encrypt_type.clone(),
        encrypt_check,
        database: PathBuf::from("master.db"),
        metadata: vec![],
    };
    let config_path = vault_path.join("master.json");
    let config_json = serde_json::to_string(&new_config)?;
    fs::write(config_path, config_json)?;

    let conn = Connection::open(vault_path.join(&new_config.database))?;

    if encrypt_type == EncryptionType::Aes256Gcm {
        if let Some(p) = password {
            // [核心修正] 使用 pragma_update 函数。这是最安全、最正确的方式。
            // 它不需要手动处理 SQL 注入，并且能正确地更新连接状态。
            conn.pragma_update(None, "key", p)?;
        }
    }

    // `execute_batch` for table creation remains the same and is correct.
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS files (
            sha256sum           TEXT PRIMARY KEY NOT NULL,
            name                TEXT NOT NULL UNIQUE,
            encrypt_type        INTEGER NOT NULL,
            encrypt_password    TEXT NOT NULL,
            encrypt_check       TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS tags (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            file_sha256sum      TEXT NOT NULL,
            tag                 TEXT NOT NULL,
            FOREIGN KEY (file_sha256sum) REFERENCES files(sha256sum) ON DELETE CASCADE
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_link ON tags(file_sha256sum, tag);
         CREATE TABLE IF NOT EXISTS metadata (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            file_sha256sum      TEXT NOT NULL,
            meta_key            TEXT NOT NULL,
            meta_value          TEXT NOT NULL,
            FOREIGN KEY (file_sha256sum) REFERENCES files(sha256sum) ON DELETE CASCADE
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_meta_link ON metadata(file_sha256sum, meta_key);"
    )?;


    let vault = Vault{
        root_path:vault_path.to_path_buf(),
        config: new_config,
        database_connection : conn
    };
    Ok(vault)
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("Vault path does not exist or is not a directory: {0}")]
    PathNotFound(PathBuf),

    #[error("Configuration file 'master.json' not found in vault.")]
    ConfigNotFound,

    #[error("Database file specified in config not found.")]
    DatabaseNotFound,

    #[error("Failed to read configuration file: {0}")]
    ConfigReadError(#[from] std::io::Error),

    #[error("Failed to parse configuration file: {0}")]
    ConfigParseError(#[from] serde_json::Error),

    #[error("Failed to open database: {0}")]
    DatabaseOpenError(#[from] rusqlite::Error),

    #[error("Invalid password provided for encrypted vault.")]
    InvalidPassword,

    #[error("Password required for an encrypted vault but was not provided.")]
    PasswordRequired,
}

/// Opens an existing vault from a given path.
/// 打开一个已存在的保险库。
///
/// # Arguments
/// * `vault_path` - 保险库的根目录路径。
/// * `password` - (可选) 如果保险库是加密的，必须提供正确的密码。
///
/// # Returns
/// 成功时返回一个 `Vault` 实例，否则返回 `OpenError`。
// [修改] 更新函数签名，增加 password 参数
pub fn open_vault(vault_path: &Path, password: Option<&str>) -> Result<Vault, OpenError> {
    if !vault_path.is_dir() {
        return Err(OpenError::PathNotFound(vault_path.to_path_buf()));
    }

    let config_path = vault_path.join("master.json");
    if !config_path.exists() {
        return Err(OpenError::ConfigNotFound);
    }

    let config_content = fs::read_to_string(config_path)?;
    let config: VaultConfig = serde_json::from_str(&config_content)?;

    let db_path = vault_path.join(&config.database);
    if !db_path.exists() {
        return Err(OpenError::DatabaseNotFound);
    }
    let conn = Connection::open(db_path)?;

    if config.encrypt_type == EncryptionType::Aes256Gcm {
        match password {
            Some(p) => {
                if !config.encrypt_check.verify(p) {
                    return Err(OpenError::InvalidPassword);
                }

                // [核心修正] 同样，在打开时也使用 pragma_update
                conn.pragma_update(None, "key", p)?;

                // 这个验证查询是好的，我们保留它
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
    })
}