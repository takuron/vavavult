use std::fs;
use std::path::{Path, PathBuf};
use rusqlite::{Connection, params};
use serde_json::Value;
use crate::common::constants::{CURRENT_VAULT_VERSION, META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use crate::file::encrypt::{create_v2_encrypt_check, verify_v2_encrypt_check, EncryptError};
use crate::storage::StorageBackend;
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::config::VaultConfig;
use crate::vault::create::CreateError::VaultAlreadyExists;
use crate::vault::Vault;

/// Defines errors that can occur during vault creation.
//
// // 定义在保险库创建期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The target directory already exists and is not empty.
    //
    // // 目标目录已存在且不为空。
    #[error("Vault directory already exists at {0}")]
    VaultAlreadyExists(PathBuf),

    /// An I/O error occurred while creating directories or writing files.
    //
    // // 在创建目录或写入文件时发生 I/O 错误。
    #[error("Failed to create vault directory: {0}")]
    DirectoryCreationError(#[from] std::io::Error),

    /// Failed to serialize the `master.json` configuration file.
    //
    // // 序列化 `master.json` 配置文件失败。
    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// An error occurred while initializing the SQLite database.
    //
    // // 初始化 SQLite 数据库时发生错误。
    #[error("Failed to init database: {0}")]
    DatabaseInitError(#[from] rusqlite::Error),

    /// Failed to generate the encryption password check string.
    //
    // // 创建加密密码检查字符串失败。
    #[error("Failed to create encryption check: {0}")]
    EncryptionError(#[from] EncryptError),
}

/// 创建一个新的保险库
pub(crate) fn create_vault(
    vault_path: &Path,
    vault_name: &str,
    password: Option<&str>,
    backend: Box<dyn StorageBackend>
) -> Result<Vault, CreateError> {
    if vault_path.exists() && fs::read_dir(vault_path)?.next().is_some(){
        return  Err(VaultAlreadyExists(vault_path.to_path_buf()));
    } else {
        fs::create_dir_all(vault_path)?;
    }

    let encrypted = password.is_some();
    let encrypt_check = if let Some(p) = password {
        create_v2_encrypt_check(p)?
    } else {
        "".to_string()
    };

    let new_config = VaultConfig {
        name: vault_name.to_string(),
        version: CURRENT_VAULT_VERSION,
        encrypted,
        encrypt_check,
        database: PathBuf::from("master.db"),
    };

    let config_path = vault_path.join("master.json");
    let config_json = serde_json::to_string(&new_config)?;
    fs::write(config_path, config_json)?;

    let conn = Connection::open(vault_path.join(&new_config.database))?;

    if encrypted {
        if let Some(p) = password {
            conn.pragma_update(None, "key", p)?;
        }
    }

    conn.execute_batch(
        "PRAGMA foreign_keys = ON;

         CREATE TABLE IF NOT EXISTS vault_metadata (
            meta_key            TEXT PRIMARY KEY NOT NULL,
            meta_value          TEXT NOT NULL
         );

         CREATE TABLE IF NOT EXISTS files (
            sha256sum           CHAR(43) PRIMARY KEY NOT NULL,
            path                TEXT NOT NULL UNIQUE,
            original_sha256sum  CHAR(43) NOT NULL UNIQUE,
            encrypt_password    TEXT NOT NULL
         );

         CREATE TABLE IF NOT EXISTS tags (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            file_sha256sum      CHAR(43) NOT NULL,
            tag                 TEXT NOT NULL,
            FOREIGN KEY (file_sha256sum) REFERENCES files(sha256sum) ON DELETE CASCADE
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_link ON tags(file_sha256sum, tag);

         CREATE TABLE IF NOT EXISTS metadata (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            file_sha256sum      CHAR(43) NOT NULL,
            meta_key            TEXT NOT NULL,
            meta_value          TEXT NOT NULL,
            FOREIGN KEY (file_sha256sum) REFERENCES files(sha256sum) ON DELETE CASCADE
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_meta_link ON metadata(file_sha256sum, meta_key);"
    )?;

    // 将保险库元数据插入到新表中
    let now = now_as_rfc3339_string();
    conn.execute(
        "INSERT INTO vault_metadata (meta_key, meta_value) VALUES (?1, ?2), (?3, ?4)",
        params![
            META_VAULT_CREATE_TIME,
            &now,
            META_VAULT_UPDATE_TIME,
            &now
        ],
    )?;

    let vault = Vault {
        root_path: vault_path.to_path_buf(),
        config: new_config,
        database_connection: conn,
        storage: backend,
    };
    Ok(vault)
}

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
    backend: Box<dyn StorageBackend>
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