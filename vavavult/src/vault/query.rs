use std::collections::HashSet;
use rusqlite::{params, OptionalExtension, Connection};
use crate::common::metadata::MetadataEntry;
use crate::file::FileEntry;
use crate::utils::path::normalize_path_name;
use crate::vault::Vault;

/// 查询操作的返回结果。(保持不变)
#[derive(Debug)]
pub enum QueryResult {
    NotFound,
    Found(FileEntry),
}

/// 查询操作中可能发生的错误。(保持不变)
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("Data inconsistency: Record for SHA256 '{0}' found in DB, but file is missing from data store.")]
    FileMissing(String),

    #[error("Failed to deserialize data: {0}")]
    DeserializationError(#[from] serde_json::Error),
}

/// [V2 修改] 一个内部辅助函数，用于从数据库中获取一个 V2 文件的完整信息。
fn fetch_full_entry(
    conn: &Connection,
    sha256sum: &str,          // 加密后哈希 (Base64)
    path: &str,               // 文件路径
    original_sha256sum: &str, // 原始哈希 (Base64)
    encrypt_password: &str    // 文件密码
) -> Result<FileEntry, QueryError> {

    // [V2 修改] 查询标签 (外键现在是加密后哈希)
    let mut tags_stmt = conn.prepare("SELECT tag FROM tags WHERE file_sha256sum = ?1")?;
    let tags = tags_stmt.query_map(params![sha256sum], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    // [V2 修改] 查询元数据 (外键现在是加密后哈希)
    let mut meta_stmt = conn.prepare("SELECT meta_key, meta_value FROM metadata WHERE file_sha256sum = ?1")?;
    let metadata = meta_stmt.query_map(params![sha256sum], |row| {
        Ok(MetadataEntry {
            key: row.get(0)?,
            value: row.get(1)?,
        })
    })?.collect::<Result<Vec<MetadataEntry>, _>>()?;

    // [V2 修改] 构建 V2 FileEntry
    Ok(FileEntry {
        sha256sum: sha256sum.to_string(),
        path: path.to_string(), // V2 使用 'path'
        original_sha256sum: original_sha256sum.to_string(),
        encrypt_password: encrypt_password.to_string(),
        tags,
        metadata,
        // encrypt_type 和 encrypt_check 已移除
    })
}


/// [V2 修改] 根据文件路径 (`&str`) 在保险库中查找文件。
pub fn check_by_name(vault: &Vault, name: &str) -> Result<QueryResult, QueryError> {
    // [新增] 在查询前规范化路径字符串
    let normalized_path = normalize_path_name(name);

    // [V2 修改] 查询 V2 files 表
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path = ?1"
    )?;

    // [修改] 使用规范化路径查询
    if let Some(res) = stmt.query_row(params![normalized_path], |row| {
        Ok((
            row.get::<_, String>(0)?, // sha256sum (加密后)
            row.get::<_, String>(1)?, // path
            row.get::<_, String>(2)?, // original_sha256sum
            row.get::<_, String>(3)?, // encrypt_password
        ))
    }).optional()? {
        // [V2 修改] 解构 V2 字段
        let (sha256sum, path, original_sha256sum, encrypt_password) = res;

        // [V2 修改] 文件存储在 data 子目录中，文件名是其加密后哈希
        let expected_path = vault.root_path.join(crate::common::constants::DATA_SUBDIR).join(&sha256sum);
        if !expected_path.exists() {
            // 文件缺失错误仍然基于加密后哈希
            return Err(QueryError::FileMissing(sha256sum));
        }

        // [V2 修改] 使用 V2 字段调用 fetch_full_entry
        let entry = fetch_full_entry(&vault.database_connection, &sha256sum, &path, &original_sha256sum, &encrypt_password)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 根据文件的加密后 SHA256 哈希值 (Base64 `&str`) 在保险库中查找文件。
pub fn check_by_hash(vault: &Vault, sha256sum: &str) -> Result<QueryResult, QueryError> {
    // [V2 修改] 查询 V2 files 表
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE sha256sum = ?1"
    )?;

    // [修改] 参数现在是加密后哈希
    if let Some(res) = stmt.query_row(params![sha256sum], |row| {
        Ok((
            row.get::<_, String>(0)?, // sha256sum (加密后)
            row.get::<_, String>(1)?, // path
            row.get::<_, String>(2)?, // original_sha256sum
            row.get::<_, String>(3)?, // encrypt_password
        ))
    }).optional()? {
        // [V2 修改] 解构 V2 字段
        let (ret_sha256sum, path, original_sha256sum, encrypt_password) = res;
        // 确认返回的哈希与查询的哈希一致 (虽然理论上应该总是如此)
        assert_eq!(ret_sha256sum, sha256sum);

        // [V2 修改] 检查 data 子目录中的文件
        let expected_path = vault.root_path.join(crate::common::constants::DATA_SUBDIR).join(&sha256sum);
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        // [V2 修改] 使用 V2 字段调用 fetch_full_entry
        let entry = fetch_full_entry(&vault.database_connection, sha256sum, &path, &original_sha256sum, &encrypt_password)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 根据文件的 *原始* SHA256 哈希值 (Base64 `&str`) 在保险库中查找文件。
pub fn check_by_original_hash(vault: &Vault, original_sha256sum: &str) -> Result<QueryResult, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE original_sha256sum = ?1"
    )?;

    // [修改] 参数现在是 *原始* 哈希
    if let Some(res) = stmt.query_row(params![original_sha256sum], |row| {
        Ok((
            row.get::<_, String>(0)?, // sha256sum (加密后)
            row.get::<_, String>(1)?, // path
            row.get::<_, String>(2)?, // original_sha256sum
            row.get::<_, String>(3)?, // encrypt_password
        ))
    }).optional()? {
        // 解构 V2 字段
        let (sha256sum, path, ret_original_sha256sum, encrypt_password) = res;
        // 确认返回的哈希与查询的哈希一致
        assert_eq!(ret_original_sha256sum, original_sha256sum);

        // 检查 data 子目录中的文件
        let expected_path = vault.root_path.join(crate::common::constants::DATA_SUBDIR).join(&sha256sum);
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        // 使用 V2 字段调用 fetch_full_entry
        let entry = fetch_full_entry(&vault.database_connection, &sha256sum, &path, original_sha256sum, &encrypt_password)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// Represents the result of listing a path's contents. (保持不变)
#[derive(Debug, Default)]
pub struct ListResult {
    pub files: Vec<FileEntry>, // 将包含 V2 FileEntry
    pub subdirectories: Vec<String>,
}

/// A helper function to normalize a path string for querying. (保持不变)
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

/// [V2 修改] A helper function to process a list of raw DB rows into a Vec of V2 FileEntry.
fn process_rows_to_entries(
    vault: &Vault,
    // [修改] 行元组现在包含 V2 字段
    rows: Vec<(String, String, String, String)>,
) -> Result<Vec<FileEntry>, QueryError> {
    let mut entries = Vec::with_capacity(rows.len());
    // [修改] 解构 V2 字段
    for (sha256sum, path, original_sha256sum, encrypt_password) in rows {
        let entry = fetch_full_entry(
            &vault.database_connection,
            &sha256sum,
            &path,
            &original_sha256sum,
            &encrypt_password,
        )?;
        entries.push(entry);
    }
    Ok(entries)
}

/// [V2 修改] Lists all files in the vault.
pub fn list_all_files(vault: &Vault) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] 查询 V2 files 表
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files",
    )?;

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // 使用 V2 的 process_rows_to_entries
    process_rows_to_entries(vault, rows)
}

/// [V2 修改] Lists files and subdirectories directly under a given path string.
pub fn list_by_path(vault: &Vault, path: &str) -> Result<ListResult, QueryError> {
    let normalized_path = normalize_query_path(path);
    let mut result = ListResult::default();
    let mut seen_subdirs = HashSet::new();

    // [修改] 查询 V2 files 表的 'path' 字段
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path LIKE ?1",
    )?;
    let like_pattern = format!("{}%", normalized_path);

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // [修改] 解构 V2 字段
    for (sha256sum, file_path, original_sha256sum, encrypt_password) in rows {
        // [修改] 使用 'file_path' 进行逻辑判断
        let remainder = file_path.strip_prefix(&normalized_path).unwrap_or("");

        if remainder.contains('/') {
            if let Some(subdir) = remainder.split('/').next() {
                if !subdir.is_empty() && seen_subdirs.insert(subdir.to_string()) {
                    result.subdirectories.push(subdir.to_string());
                }
            }
        } else {
            // [修改] 使用 V2 字段调用 fetch_full_entry
            let full_entry = fetch_full_entry(
                &vault.database_connection,
                &sha256sum,
                &file_path,
                &original_sha256sum,
                &encrypt_password,
            )?;
            result.files.push(full_entry);
        }
    }

    // [修改] 按 V2 FileEntry.path 排序
    result.files.sort_by(|a, b| a.path.cmp(&b.path));
    result.subdirectories.sort();

    Ok(result)
}

/// [V2 修改] Finds all files associated with a specific tag.
pub fn find_by_tag(vault: &Vault, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] JOIN files f ... 选择 V2 字段
    let mut stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
         FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE t.tag = ?1",
    )?;

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map(params![tag], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// [V2 修改] Finds all files whose path contains a given pattern.
pub fn find_by_name_fuzzy(vault: &Vault, name_pattern: &str) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] 查询 V2 files 表，按 'path' 字段进行 LIKE 匹配
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password
         FROM files WHERE path LIKE ?1",
    )?;
    let like_pattern = format!("%{}%", name_pattern);

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// [V2 修改] Finds all files matching a path pattern and a specific tag.
#[deprecated(since = "0.2.2", note = "Please use `find_by_name_or_tag_fuzzy` instead for combined searching")]
pub fn find_by_name_and_tag_fuzzy(
    vault: &Vault,
    name_pattern: &str,
    tag: &str,
) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] JOIN files f ... 选择 V2 字段，按 'f.path' 匹配
    let mut stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
         FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE f.path LIKE ?1 AND t.tag = ?2",
    )?;
    let like_pattern = format!("%{}%", name_pattern);

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map(params![like_pattern, tag], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// [V2 修改] Finds all files whose path OR tags contain a given pattern.
pub fn find_by_name_or_tag_fuzzy(
    vault: &Vault,
    keyword: &str,
) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] 使用 LEFT JOIN，匹配 f.path 或 t.tag
    let mut stmt = vault.database_connection.prepare(
        "SELECT DISTINCT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
         FROM files f LEFT JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE f.path LIKE ?1 OR t.tag LIKE ?1", // 匹配 f.path
    )?;
    let like_pattern = format!("%{}%", keyword);

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}