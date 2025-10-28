use std::collections::HashSet;
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

/// Represents the result of listing a path's contents.
#[derive(Debug, Default)]
pub struct ListResult {
    pub files: Vec<FileEntry>,
    pub subdirectories: Vec<String>,
}

/// A helper function to normalize a path for querying.
/// Ensures it starts with "/" and, if not the root, ends with "/".
fn normalize_query_path(path: &str) -> String {
    let mut normalized = String::from("/");
    let trimmed = path.trim_matches('/');
    if !trimmed.is_empty() {
        normalized.push_str(trimmed);
        normalized.push('/');
    }
    normalized
}

/// A helper function to process a list of raw DB rows into a Vec of FileEntry.
fn process_rows_to_entries(
    vault: &Vault,
    rows: Vec<(String, String, EncryptionType, String, String)>,
) -> Result<Vec<FileEntry>, QueryError> {
    let mut entries = Vec::with_capacity(rows.len());
    for (sha256sum, name, encrypt_type, encrypt_password, encrypt_check_json) in rows {
        let entry = fetch_full_entry(
            &vault.database_connection,
            &sha256sum,
            &name,
            encrypt_type,
            &encrypt_password,
            &encrypt_check_json,
        )?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Lists all files in the vault.
pub fn list_all_files(vault: &Vault) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, name, encrypt_type, encrypt_password, encrypt_check FROM files",
    )?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, EncryptionType>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// Lists files and subdirectories directly under a given path.
pub fn list_by_path(vault: &Vault, path: &str) -> Result<ListResult, QueryError> {
    let normalized_path = normalize_query_path(path);
    let mut result = ListResult::default();
    let mut seen_subdirs = HashSet::new();

    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, name, encrypt_type, encrypt_password, encrypt_check FROM files WHERE name LIKE ?1",
    )?;
    let like_pattern = format!("{}%", normalized_path);

    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, EncryptionType>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (sha256sum, name, encrypt_type, encrypt_password, encrypt_check_json) in rows {
        let remainder = name.strip_prefix(&normalized_path).unwrap_or("");

        if remainder.contains('/') {
            if let Some(subdir) = remainder.split('/').next() {
                if !subdir.is_empty() && seen_subdirs.insert(subdir.to_string()) {
                    result.subdirectories.push(subdir.to_string());
                }
            }
        } else {
            let full_entry = fetch_full_entry(
                &vault.database_connection,
                &sha256sum,
                &name,
                encrypt_type,
                &encrypt_password,
                &encrypt_check_json,
            )?;
            result.files.push(full_entry);
        }
    }

    result.files.sort_by(|a, b| a.name.cmp(&b.name));
    result.subdirectories.sort();

    Ok(result)
}

/// Finds all files associated with a specific tag.
pub fn find_by_tag(vault: &Vault, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.name, f.encrypt_type, f.encrypt_password, f.encrypt_check
         FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE t.tag = ?1",
    )?;

    let rows = stmt
        .query_map(params![tag], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, EncryptionType>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// Finds all files whose name contains a given pattern.
pub fn find_by_name_fuzzy(vault: &Vault, name_pattern: &str) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, name, encrypt_type, encrypt_password, encrypt_check
         FROM files WHERE name LIKE ?1",
    )?;
    let like_pattern = format!("%{}%", name_pattern);

    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, EncryptionType>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// Finds all files matching a name pattern and a specific tag.
pub fn find_by_name_and_tag_fuzzy(
    vault: &Vault,
    name_pattern: &str,
    tag: &str,
) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.name, f.encrypt_type, f.encrypt_password, f.encrypt_check
         FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE f.name LIKE ?1 AND t.tag = ?2",
    )?;
    let like_pattern = format!("%{}%", name_pattern);

    let rows = stmt
        .query_map(params![like_pattern, tag], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, EncryptionType>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// Finds all files whose name OR tags contain a given pattern.
// 查找所有名称或标签包含给定模式的文件。
pub fn find_by_name_or_tag_fuzzy(
    vault: &Vault,
    keyword: &str,
) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        // [核心修改] 使用 LEFT JOIN 和 OR 来同时匹配 f.name 和 t.tag
        // 使用 DISTINCT 确保即使一个文件有多个标签匹配，也只返回一次
        "SELECT DISTINCT f.sha256sum, f.name, f.encrypt_type, f.encrypt_password, f.encrypt_check
         FROM files f LEFT JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE f.name LIKE ?1 OR t.tag LIKE ?1",
    )?;
    let like_pattern = format!("%{}%", keyword);

    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, EncryptionType>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}