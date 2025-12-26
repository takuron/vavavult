use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use rusqlite::{Connection, params};
use crate::common::constants::{CURRENT_VAULT_VERSION, META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use crate::crypto::encrypt::{create_v2_encrypt_check,  EncryptError};
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
    backend: Arc<dyn StorageBackend>
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

