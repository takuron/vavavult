use std::fs;
use std::path::{Path, PathBuf};
use rusqlite::Connection;
use crate::file::encrypt::{EncryptionCheck, EncryptionType};
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
}

pub fn create_vault(vault_path: &Path, vault_name: &str) -> Result<Vault, CreateError>{
    //判断目录为空来创建
    if vault_path.exists()&&fs::read_dir(vault_path)?.next().is_some(){
        return  Err(VaultAlreadyExists(vault_path.to_path_buf()));
    } else {
        fs::create_dir_all(vault_path)?;
    }

    //初始化master.json
    let new_config = VaultConfig {
        name: vault_name.to_string(),
        version: 1,
        encrypt_type: EncryptionType::None,
        encrypt_check: EncryptionCheck {
            raw: "".to_string(), // 一个无意义的字符串
            encrypted: "".to_string(),      // 未加密，所以为空
        },
        database: PathBuf::from("master.db"),
        metadata: vec![],
    };
    let config_path = vault_path.join("master.json");
    let config_json = serde_json::to_string(&new_config)?;
    fs::write(config_path, config_json)?;

    //初始化master.db
    let conn = Connection::open(vault_path.join(&new_config.database))?;
    let tx = conn.unchecked_transaction()?;
    tx.execute("PRAGMA foreign_keys = ON;", [])?;
    tx.execute(
        "CREATE TABLE IF NOT EXISTS files (
                sha256sum           TEXT PRIMARY KEY NOT NULL,
                name                TEXT NOT NULL UNIQUE,
                encrypt_type        INTEGER NOT NULL,
                encrypt_password    TEXT NOT NULL,
                encrypt_check       TEXT NOT NULL
            )",
        [],
    )?;
    tx.execute(
        "CREATE TABLE IF NOT EXISTS tags (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                file_sha256sum      TEXT NOT NULL,
                tag                 TEXT NOT NULL,
                FOREIGN KEY (file_sha256sum) REFERENCES files(sha256sum) ON DELETE CASCADE
            )",
        [],
    )?;
    tx.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_link ON tags(file_sha256sum, tag)",
        [],
    )?;
    tx.execute(
        "CREATE TABLE IF NOT EXISTS metadata (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                file_sha256sum      TEXT NOT NULL,
                meta_key            TEXT NOT NULL,
                meta_value          TEXT NOT NULL,
                FOREIGN KEY (file_sha256sum) REFERENCES files(sha256sum) ON DELETE CASCADE
            )",
        [],
    )?;
    tx.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_meta_link ON metadata(file_sha256sum, meta_key)",
        [],
    )?;
    tx.commit()?;

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
}

/// Opens an existing vault from a given path.
pub fn open_vault(vault_path: &Path) -> Result<Vault, OpenError> {
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

    Ok(Vault {
        root_path: vault_path.to_path_buf(),
        config,
        database_connection: conn,
    })
}