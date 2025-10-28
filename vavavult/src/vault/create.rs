use std::fs;
use std::path::{Path, PathBuf};
use rusqlite::{Connection, params};
use serde_json::Value;
use crate::common::constants::{CURRENT_VAULT_VERSION, META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use crate::file::encrypt::{create_v2_encrypt_check, verify_v2_encrypt_check, EncryptError};
use crate::utils::time::now_as_rfc3339_string;
use crate::vault::config::VaultConfig;
use crate::vault::create::CreateError::VaultAlreadyExists;
use crate::vault::Vault;

#[derive(Debug, thiserror::Error)] 
pub enum CreateError {
    #[error("Vault directory already exists at {0}")]
    VaultAlreadyExists(PathBuf),

    #[error("Failed to create vault directory: {0}")]
    DirectoryCreationError(#[from] std::io::Error),

    #[error("Failed to serialize configuration: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Failed to init database: {0}")]
    DatabaseInitError(#[from] rusqlite::Error),

    #[error("Failed to create encryption check: {0}")]
    EncryptionError(#[from] EncryptError),
}

/// 创建一个新的保险库 (V2)。
pub fn create_vault(vault_path: &Path, vault_name: &str, password: Option<&str>) -> Result<Vault, CreateError>{
    if vault_path.exists() && fs::read_dir(vault_path)?.next().is_some(){
        return  Err(VaultAlreadyExists(vault_path.to_path_buf()));
    } else {
        fs::create_dir_all(vault_path)?;
    }

    let encrypted = password.is_some();
    let encrypt_check = if let Some(p) = password {
        // [修改] (请求 1) 直接调用，函数内部会生成随机 raw
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

    // [V2 修改] (请求 2) 更新数据库表结构，使用 CHAR(43)
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;

         CREATE TABLE IF NOT EXISTS vault_metadata (
            meta_key            TEXT PRIMARY KEY NOT NULL,
            meta_value          TEXT NOT NULL
         );

         CREATE TABLE IF NOT EXISTS files (
            sha256sum           CHAR(43) PRIMARY KEY NOT NULL,  
            path                TEXT NOT NULL UNIQUE,
            original_sha256sum  CHAR(43) NOT NULL,              
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

    // [V2 新增] 将保险库元数据插入到新表中
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

    let vault = Vault{
        root_path:vault_path.to_path_buf(),
        config: new_config,
        database_connection : conn
    };
    Ok(vault)
}

#[derive(Debug, thiserror::Error)] // (OpenError 枚举保持不变)
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

    #[error("Unsupported vault version: found {found}, but this library supports version {supported}.")]
    UnsupportedVersion {
        supported: u32,
        found: u32,
    },
}

/// 打开一个已存在的保险库 (V2)。
pub fn open_vault(vault_path: &Path, password: Option<&str>) -> Result<Vault, OpenError> {
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
    })
}