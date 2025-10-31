use std::collections::HashSet;
use rusqlite::{params, OptionalExtension, Connection};
use crate::common::metadata::MetadataEntry;
use crate::file::{FileEntry, PathError, VaultPath};
use crate::vault::Vault;
use crate::common::hash::{VaultHash, HashParseError};

/// Represents the result of a query that seeks a single `FileEntry`.
//
// // 代表寻求单个 `FileEntry` 的查询结果。
#[derive(Debug)]
pub enum QueryResult {
    NotFound,
    Found(FileEntry),
}

/// Defines errors that can occur during a query operation.
//
// // 定义在查询操作期间可能发生的错误。
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// An error occurred while interacting with the database.
    //
    // // 与数据库交互时发生错误。
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// Data inconsistency: A record was found in the database, but the corresponding
    /// encrypted file is missing from the `data/` directory.
    //
    // // 数据不一致：在数据库中找到了记录，但 `data/` 目录中缺少
    // // 相应的加密文件。
    #[error("Data inconsistency: Record for SHA256 '{0}' found in DB, but file is missing from data store.")]
    FileMissing(String),

    /// Failed to deserialize data (e.g., metadata).
    //
    // // 反序列化数据失败 (例如元数据)。
    #[error("Failed to deserialize data: {0}")]
    DeserializationError(#[from] serde_json::Error),

    /// A hash string failed to parse.
    //
    // // 哈希字符串解析失败。
    #[error("Hash parsing error: {0}")]
    HashParse(#[from] HashParseError),

    /// A directory-listing operation was attempted on a file path.
    //
    // // 尝试在文件路径上执行目录列表操作。
    #[error("Path is not a directory: {0}")]
    NotADirectory(String),

    /// An error occurred during `VaultPath` construction.
    //
    // // `VaultPath` 构建期间发生错误。
    #[error("Path construction error: {0}")]
    PathError(#[from] PathError),
}

/// 一个内部辅助函数，用于从数据库中获取一个 V2 文件的完整信息。
fn fetch_full_entry(
    conn: &Connection,
    sha256sum: &VaultHash,          // [修改]
    path: VaultPath,               // 文件路径
    original_sha256sum: &VaultHash, // [修改]
    encrypt_password: &str    // 文件密码
) -> Result<FileEntry, QueryError> {

    // 查询标签 (外键现在是加密后哈希)
    // `params![sha256sum]` 将自动工作 (ToSql)
    let mut tags_stmt = conn.prepare("SELECT tag FROM tags WHERE file_sha256sum = ?1")?;
    let tags = tags_stmt.query_map(params![sha256sum], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    // 查询元数据 (外键现在是加密后哈希)
    // `params![sha256sum]` 将自动工作 (ToSql)
    let mut meta_stmt = conn.prepare("SELECT meta_key, meta_value FROM metadata WHERE file_sha256sum = ?1")?;
    let metadata = meta_stmt.query_map(params![sha256sum], |row| {
        Ok(MetadataEntry {
            key: row.get(0)?,
            value: row.get(1)?,
        })
    })?.collect::<Result<Vec<MetadataEntry>, _>>()?;

    // 构建 V2 FileEntry
    Ok(FileEntry {
        sha256sum: sha256sum.clone(),
        path,
        original_sha256sum: original_sha256sum.clone(),
        encrypt_password: encrypt_password.to_string(),
        tags,
        metadata,
        // encrypt_type 和 encrypt_check 已移除
    })
}


/// 根据文件路径 (`&str`) 在保险库中查找文件。
pub fn check_by_path(vault: &Vault, path: &VaultPath) -> Result<QueryResult, QueryError> {
    // VaultPath 已经是规范化的
    let normalized_path = path.as_str();

    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path = ?1"
    )?;

    if let Some(res) = stmt.query_row(params![normalized_path], |row| {
        Ok((
            row.get::<_, VaultHash>(0)?,
            row.get::<_, VaultPath>(1)?,
            row.get::<_, VaultHash>(2)?,
            row.get::<_, String>(3)?,
        ))
    }).optional()? {
        let (sha256sum, path, original_sha256sum, encrypt_password) = res;

        let expected_path = vault.root_path.join(crate::common::constants::DATA_SUBDIR).join(sha256sum.to_string());
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        let entry = fetch_full_entry(&vault.database_connection, &sha256sum, path, &original_sha256sum, &encrypt_password)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 根据文件的加密后 SHA256 哈希值 (Base64 `&str`) 在保险库中查找文件。
pub fn check_by_hash(vault: &Vault, hash: &VaultHash) -> Result<QueryResult, QueryError> { // [修改]
    // 查询 V2 files 表
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE sha256sum = ?1"
    )?;

    // 参数现在是加密后哈希 (ToSql)
    if let Some(res) = stmt.query_row(params![hash], |row| {
        Ok((
            row.get::<_, VaultHash>(0)?,
            row.get::<_, VaultPath>(1)?,
            row.get::<_, VaultHash>(2)?,
            row.get::<_, String>(3)?,
        ))
    }).optional()? {
        // 解构 V2 字段
        let (ret_sha256sum, path, original_sha256sum, encrypt_password) = res;
        // 确认返回的哈希与查询的哈希一致 (虽然理论上应该总是如此)
        assert_eq!(ret_sha256sum, *hash);

        // 检查 data 子目录中的文件
        let expected_path = vault.root_path.join(crate::common::constants::DATA_SUBDIR).join(hash.to_string());
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(hash.to_string()));
        }

        // 使用 V2 字段调用 fetch_full_entry
        let entry = fetch_full_entry(&vault.database_connection, hash,path, &original_sha256sum, &encrypt_password)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 根据文件的 *原始* SHA256 哈希值 (Base64 `&str`) 在保险库中查找文件。
pub fn check_by_original_hash(vault: &Vault, original_hash: &VaultHash) -> Result<QueryResult, QueryError> { // [修改]
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE original_sha256sum = ?1"
    )?;

    // [修改] 参数现在是 *原始* 哈希 (ToSql)
    if let Some(res) = stmt.query_row(params![original_hash], |row| {
        Ok((
            row.get::<_, VaultHash>(0)?, // [修改]
            row.get::<_, VaultPath>(1)?,
            row.get::<_, VaultHash>(2)?, // [修改]
            row.get::<_, String>(3)?,
        ))
    }).optional()? {
        // 解构 V2 字段
        let (sha256sum, path, ret_original_sha256sum, encrypt_password) = res;
        // 确认返回的哈希与查询的哈希一致
        assert_eq!(ret_original_sha256sum, *original_hash);

        // 检查 data 子目录中的文件
        let expected_path = vault.root_path.join(crate::common::constants::DATA_SUBDIR).join(sha256sum.to_string());
        if !expected_path.exists() {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        // 使用 V2 字段调用 fetch_full_entry
        let entry = fetch_full_entry(&vault.database_connection, &sha256sum, path, original_hash, &encrypt_password)?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// Represents the result of listing a directory's contents (non-recursive).
//
// // 代表列出目录内容的结果（非递归）。
#[derive(Debug, Default)]
pub struct ListResult {
    /// A list of files found directly in that directory.
    //
    // // 在该目录中直接找到的文件列表。
    pub files: Vec<FileEntry>,
    /// A list of subdirectory names (not full paths) found.
    //
    // // 找到的子目录名称列表（非完整路径）。
    pub subdirectories: Vec<String>,
}

/// A helper function to normalize a path string for querying.
/// Ensures it starts with "/" and, if not the root, ends with "/".
// fn normalize_query_path(path: &str) -> String {
//     let mut normalized = String::from("/");
//     let trimmed = path.trim_matches('/');
//     if !trimmed.is_empty() {
//         normalized.push_str(trimmed);
//         normalized.push('/');
//     }
//     normalized
// }

/// 一个内部辅助函数，用于将原始 DB 行处理为 `FileEntry` 列表。
fn process_rows_to_entries(
    vault: &Vault,
    // [修改] 行元组现在包含 V2 字段
    rows: Vec<(VaultHash, VaultPath, VaultHash, String)>,
) -> Result<Vec<FileEntry>, QueryError> {
    let mut entries = Vec::with_capacity(rows.len());
    // [修改] 解构 V2 字段
    for (sha256sum, path, original_sha256sum, encrypt_password) in rows {
        let entry = fetch_full_entry(
            &vault.database_connection,
            &sha256sum,
            path,
            &original_sha256sum,
            &encrypt_password,
        )?;
        entries.push(entry);
    }
    Ok(entries)
}

/// 列出保险库中的所有文件 (返回 FileEntry)。
pub fn list_all_files(vault: &Vault) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] 查询 V2 files 表
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files",
    )?;

    // [修改] 映射 V2 字段
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // 使用 V2 的 process_rows_to_entries
    process_rows_to_entries(vault, rows)
}

/// 仅列出给定目录路径下的文件和子目录 (非递归)。
pub(super) fn list_by_path(vault: &Vault, path: &VaultPath) -> Result<Vec<VaultPath>, QueryError> {
    // 1. 验证输入是否为目录
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    let mut entries = Vec::new();
    let mut seen_subdirs = HashSet::new();
    let base_path_str = path.as_str();

    // 2. 查询所有以该路径为前缀的条目
    let mut stmt = vault.database_connection.prepare(
        "SELECT path FROM files WHERE path LIKE ?1",
    )?;
    let like_pattern = format!("{}%", base_path_str);
    let paths_iter = stmt.query_map(params![like_pattern], |row| row.get::<_, String>(0))?;

    for path_result in paths_iter {
        let file_path_str = path_result?; // file_path_str is String
        // 3. 计算相对路径
        let remainder = file_path_str.strip_prefix(base_path_str).unwrap_or("");

        if remainder.contains('/') {
            // 4. 这是一个子目录或更深层的文件
            if let Some(subdir_name) = remainder.split('/').next() {
                if !subdir_name.is_empty() {
                    // 我们必须将 subdir_name 作为一个目录段 (带斜杠) 来连接
                    let subdir_segment = format!("{}/", subdir_name);
                    let dir_path = path.join(&subdir_segment)?; // 例如 "/".join("docs/")

                    if seen_subdirs.insert(dir_path.clone()) {
                        entries.push(dir_path);
                    }
                }
            }
        } else if !remainder.is_empty() {
            // 5. 这是一个直属文件
            // 将 String 转换为 &str 再调用 from
            entries.push(VaultPath::from(file_path_str.as_str()));
        }
    }

    // 6. 排序
    entries.sort();
    Ok(entries)
}

/// 递归列出一个目录下的所有文件 (返回哈希)。
/// (满足您的请求 2)
pub(super) fn list_all_recursive(vault: &Vault, path: &VaultPath) -> Result<Vec<VaultHash>, QueryError> {
    // 1. 验证输入是否为目录
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    // 2. [修正] 查询 sha256sum 字段
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum FROM files WHERE path LIKE ?1",
    )?;
    let like_pattern = format!("{}%", path.as_str());

    // 3. [修正] 映射结果为 VaultHash
    let hashes = stmt
        .query_map(params![like_pattern], |row| {
            row.get::<_, VaultHash>(0) // 直接从 DB 读取 VaultHash
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(hashes)
}

/// 按特定标签查找文件。
pub fn find_by_tag(vault: &Vault, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
    // JOIN files f ... 选择 V2 字段
    let mut stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
         FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE t.tag = ?1",
    )?;

    //  映射 V2 字段
    let rows = stmt
        .query_map(params![tag], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// [新增] 统一的关键字模糊搜索 (不区分大小写)。
pub(super) fn find_by_keyword(vault: &Vault, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
    // 1. 准备不区分大小写的 LIKE 模式
    let like_pattern = format!("%{}%", keyword.to_lowercase());

    // 2. 使用 LOWER() 函数进行不区分大小写的匹配
    let mut stmt = vault.database_connection.prepare(
        "SELECT DISTINCT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
         FROM files f LEFT JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE LOWER(f.path) LIKE ?1 OR LOWER(t.tag) LIKE ?1",
    )?;

    // 3. 映射 V2 字段
    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // 4. 处理行
    process_rows_to_entries(vault, rows)
}
/// 高效地获取保险库中文件的总数。
pub(super) fn get_total_file_count(vault: &Vault) -> Result<i64, QueryError> {
    let count = vault.database_connection.query_row(
        "SELECT COUNT(*) FROM files",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

// Finds all files matching a path pattern and a specific tag.
// #[deprecated(since = "0.2.2", note = "Please use `find_by_name_or_tag_fuzzy` instead for combined searching")]
// pub fn find_by_name_and_tag_fuzzy(
//     vault: &Vault,
//     name_pattern: &str,
//     tag: &str,
// ) -> Result<Vec<FileEntry>, QueryError> {
//     // [修改] JOIN files f ... 选择 V2 字段，按 'f.path' 匹配
//     let mut stmt = vault.database_connection.prepare(
//         "SELECT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
//          FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
//          WHERE f.path LIKE ?1 AND t.tag = ?2",
//     )?;
//     let like_pattern = format!("%{}%", name_pattern);
//
//     // [修改] 映射 V2 字段
//     let rows = stmt
//         .query_map(params![like_pattern, tag], |row| {
//             Ok((
//                 row.get::<_, VaultHash>(0)?,
//                 row.get::<_, String>(1)?,
//                 row.get::<_, VaultHash>(2)?,
//                 row.get::<_, String>(3)?,
//             ))
//         })?
//         .collect::<Result<Vec<_>, _>>()?;
//
//     process_rows_to_entries(vault, rows)
// }

// Finds all files whose path OR tags contain a given pattern.
// pub fn find_by_name_or_tag_fuzzy(
//     vault: &Vault,
//     keyword: &str,
// ) -> Result<Vec<FileEntry>, QueryError> {
//     // [修改] 使用 LEFT JOIN，匹配 f.path 或 t.tag
//     let mut stmt = vault.database_connection.prepare(
//         "SELECT DISTINCT f.sha256sum, f.path, f.original_sha256sum, f.encrypt_password
//          FROM files f LEFT JOIN tags t ON f.sha256sum = t.file_sha256sum
//          WHERE f.path LIKE ?1 OR t.tag LIKE ?1", // 匹配 f.path
//     )?;
//     let like_pattern = format!("%{}%", keyword);
//
//     // [修改] 映射 V2 字段
//     let rows = stmt
//         .query_map(params![like_pattern], |row| {
//             Ok((
//                 row.get::<_, VaultHash>(0)?,
//                 row.get::<_, String>(1)?,
//                 row.get::<_, VaultHash>(2)?,
//                 row.get::<_, String>(3)?,
//             ))
//         })?
//         .collect::<Result<Vec<_>, _>>()?;
//
//     process_rows_to_entries(vault, rows)
// }