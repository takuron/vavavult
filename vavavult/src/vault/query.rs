use rusqlite::{params, OptionalExtension, Connection};
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptionCheck, EncryptionType};
use crate::file::FileEntry;
use crate::vault::Vault;

/// 查询操作的返回结果。
#[derive(Debug)]
pub enum QueryResult {
    NotFound,
    Found(FileEntry),
}

/// 查询操作中可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("Data inconsistency: Record for SHA256 '{0}' found in DB, but file is missing from data store.")]
    FileMissing(String),

    #[error("Failed to deserialize data: {0}")]
    DeserializationError(#[from] serde_json::Error),
}

/// 一个内部辅助函数，用于从数据库中获取一个文件的完整信息。
fn fetch_full_entry(conn: &Connection, sha256sum: &str, name: &str, encrypt_type: EncryptionType, encrypt_password: &str, encrypt_check_json: &str) -> Result<FileEntry, QueryError> {
    // 反序列化加密检查信息
    let encrypt_check: EncryptionCheck = serde_json::from_str(encrypt_check_json)?;

    // 查询标签
    let mut tags_stmt = conn.prepare("SELECT tag FROM tags WHERE file_sha256sum = ?1")?;
    let tags = tags_stmt.query_map(params![sha256sum], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    // 查询元数据
    let mut meta_stmt = conn.prepare("SELECT meta_key, meta_value FROM metadata WHERE file_sha256sum = ?1")?;
    let metadata = meta_stmt.query_map(params![sha256sum], |row| {
        Ok(MetadataEntry {
            key: row.get(0)?,
            value: row.get(1)?,
        })
    })?.collect::<Result<Vec<MetadataEntry>, _>>()?;

    Ok(FileEntry {
        sha256sum: sha256sum.to_string(),
        name: name.to_string(),
        encrypt_type,
        encrypt_password: encrypt_password.to_string(),
        encrypt_check,
        tags,
        metadata,
    })
}


/// 根据文件名在保险库中查找文件。
pub fn check_by_name(vault: &Vault, name: &str) -> Result<QueryResult, QueryError> {
    let mut stmt = vault.database_connection.prepare("SELECT sha256sum, name, encrypt_type, encrypt_password, encrypt_check FROM files WHERE name = ?1")?;

    if let Some(res) = stmt.query_row(params![name], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, EncryptionType>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    }).optional()? {
        let (sha256sum, name, encrypt_type, encrypt_password, encrypt_check_json) = res;

        let expected_path = vault.root_path.join(&sha256sum);
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(sha256sum));
        }

        let entry = fetch_full_entry(&vault.database_connection, &sha256sum, &name, encrypt_type, &encrypt_password, &encrypt_check_json)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 根据文件的 SHA256 哈希值在保险库中查找文件。
pub fn check_by_hash(vault: &Vault, sha256sum: &str) -> Result<QueryResult, QueryError> {
    let mut stmt = vault.database_connection.prepare("SELECT sha256sum, name, encrypt_type, encrypt_password, encrypt_check FROM files WHERE sha256sum = ?1")?;

    if let Some(res) = stmt.query_row(params![sha256sum], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, EncryptionType>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    }).optional()? {
        let (sha256sum, name, encrypt_type, encrypt_password, encrypt_check_json) = res;

        let expected_path = vault.root_path.join(&sha256sum);
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        let entry = fetch_full_entry(&vault.database_connection, &sha256sum, &name, encrypt_type, &encrypt_password, &encrypt_check_json)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}
