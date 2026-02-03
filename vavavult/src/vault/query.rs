use crate::common::constants::META_VAULT_FEATURES;
use crate::common::hash::{HashParseError, VaultHash};
use crate::common::metadata::MetadataEntry;
use crate::file::{FileEntry, PathError, VaultPath};
use crate::vault::Vault;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use std::collections::HashSet;

/// Represents the result of a query that seeks a single `FileEntry`.
//
// // 代表寻求单个 `FileEntry` 的查询结果。
#[derive(Debug)]
pub enum QueryResult {
    NotFound,
    Found(FileEntry),
}

/// Represents an entry in a directory listing, distinctively identifying files and subdirectories.
///
/// This enum allows consumers to handle files (with full metadata) and subdirectories
/// differently in a single pass.
//
// // 代表目录列表中的一个条目，用于区分文件和子目录。
// //
// // 此枚举允许消费者在一次遍历中以不同方式处理文件（包含完整元数据）和子目录。
#[derive(Debug, Clone)]
pub enum DirectoryEntry {
    /// A subdirectory entry, containing only its path.
    // // 子目录条目，仅包含其路径。
    Directory(VaultPath),
    /// A file entry, containing full details (path, hash, metadata, tags, etc.).
    // // 文件条目，包含完整详细信息（路径、哈希、元数据、标签等）。
    File(FileEntry),
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

    /// An I/O error occurred while accessing the storage backend (e.g., checking file existence).
    //
    // // 访问存储后端时发生 I/O 错误 (例如检查文件是否存在)。
    #[error("Storage I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Data inconsistency: A record was found in the database, but the corresponding
    /// encrypted file is missing from the `data/` directory.
    //
    // // 数据不一致：在数据库中找到了记录，但 `data/` 目录中缺少
    // // 相应的加密文件。
    #[error(
        "Data inconsistency: Record for SHA256 '{0}' found in DB, but file is missing from data store."
    )]
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

/// 一个内部辅助函数，用于从数据库中获取一个文件的完整信息。
pub(crate) fn fetch_full_entry(
    conn: &Connection,
    sha256sum: &VaultHash,
    path: VaultPath,
    original_sha256sum: &VaultHash,
    encrypt_password: &str,
) -> Result<FileEntry, QueryError> {
    // 查询标签 (外键现在是加密后哈希)
    // `params![sha256sum]` 将自动工作 (ToSql)
    let mut tags_stmt = conn.prepare("SELECT tag FROM tags WHERE file_sha256sum = ?1")?;
    let tags = tags_stmt
        .query_map(params![sha256sum], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    // 查询元数据 (外键现在是加密后哈希)
    // `params![sha256sum]` 将自动工作 (ToSql)
    let mut meta_stmt =
        conn.prepare("SELECT meta_key, meta_value FROM metadata WHERE file_sha256sum = ?1")?;
    let metadata = meta_stmt
        .query_map(params![sha256sum], |row| {
            Ok(MetadataEntry {
                key: row.get(0)?,
                value: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<MetadataEntry>, _>>()?;

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
pub(crate) fn check_by_path(vault: &Vault, path: &VaultPath) -> Result<QueryResult, QueryError> {
    // VaultPath 已经是规范化的
    let normalized_path = path.as_str();

    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path = ?1",
    )?;

    if let Some(res) = stmt
        .query_row(params![normalized_path], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()?
    {
        let (sha256sum, path, original_sha256sum, encrypt_password) = res;

        if !vault.storage.exists(&sha256sum)? {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        let entry = fetch_full_entry(
            &vault.database_connection,
            &sha256sum,
            path,
            &original_sha256sum,
            &encrypt_password,
        )?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// A variant of `check_by_path` that does not validate physical file existence.
/// This is intended for internal operations like `fix` where the file is expected to be missing.
//
// // `check_by_path` 的一个变体，不验证物理文件是否存在。
// // 这用于 `fix` 等内部操作，因为这些操作预期文件会丢失。
pub(crate) fn check_by_path_no_validation(
    vault: &Vault,
    path: &VaultPath,
) -> Result<QueryResult, QueryError> {
    // VaultPath 已经是规范化的
    let normalized_path = path.as_str();

    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path = ?1",
    )?;

    if let Some(res) = stmt
        .query_row(params![normalized_path], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()?
    {
        let (sha256sum, path, original_sha256sum, encrypt_password) = res;

        // NOTE: No vault.storage.exists() check.

        let entry = fetch_full_entry(
            &vault.database_connection,
            &sha256sum,
            path,
            &original_sha256sum,
            &encrypt_password,
        )?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 根据文件的加密后 SHA256 哈希值 (Base64 `&str`) 在保险库中查找文件。
pub(crate) fn check_by_hash(vault: &Vault, hash: &VaultHash) -> Result<QueryResult, QueryError> {
    // 查询 files 表
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE sha256sum = ?1"
    )?;

    // 参数现在是加密后哈希 (ToSql)
    if let Some(res) = stmt
        .query_row(params![hash], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()?
    {
        // 解构字段
        let (ret_sha256sum, path, original_sha256sum, encrypt_password) = res;
        // 确认返回的哈希与查询的哈希一致 (虽然理论上应该总是如此)
        assert_eq!(ret_sha256sum, *hash);

        // 检查 data 子目录中的文件
        if !vault.storage.exists(hash)? {
            return Err(QueryError::FileMissing(hash.to_string()));
        }

        // 调用 fetch_full_entry
        let entry = fetch_full_entry(
            &vault.database_connection,
            hash,
            path,
            &original_sha256sum,
            &encrypt_password,
        )?;
        Ok(QueryResult::Found(entry))
    } else {
        Ok(QueryResult::NotFound)
    }
}

/// 批量根据哈希查找文件。
///
/// 这比循环调用 `check_by_hash` 更高效，因为它减少了对 `files` 主表的查询次数。
/// 返回的列表顺序不保证与输入的哈希顺序一致。未找到的哈希将被忽略。
pub(crate) fn find_by_hashes(
    vault: &Vault,
    hashes: &[VaultHash],
) -> Result<Vec<FileEntry>, QueryError> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    // 1. 动态构建 SQL: "SELECT ... WHERE sha256sum IN (?1, ?2, ...)"
    let placeholders: Vec<String> = (1..=hashes.len()).map(|i| format!("?{}", i)).collect();
    let query_sql = format!(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE sha256sum IN ({})",
        placeholders.join(",")
    );

    // 2. 准备语句
    let mut stmt = vault.database_connection.prepare(&query_sql)?;

    // 3. 执行查询并映射结果
    // params_from_iter 允许我们将 &[VaultHash] 转换为 SQL 参数
    let rows = stmt.query_map(params_from_iter(hashes), |row| {
        Ok((
            row.get::<_, VaultHash>(0)?,
            row.get::<_, VaultPath>(1)?,
            row.get::<_, VaultHash>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    // 4. 处理结果 (这里会为每个找到的文件调用 fetch_full_entry 获取 tags/metadata)
    // 虽然 tags/metadata 仍然是 N+1 查询，但我们节省了 N 次主表查询
    process_rows_to_entries(vault, rows.collect::<Result<Vec<_>, _>>()?)
}

///  批量根据路径查找文件。
///
/// 返回的列表顺序不保证与输入的路径顺序一致。未找到的路径将被忽略。
pub(crate) fn find_by_paths(
    vault: &Vault,
    paths: &[VaultPath],
) -> Result<Vec<FileEntry>, QueryError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    // 1. 动态构建 SQL
    let placeholders: Vec<String> = (1..=paths.len()).map(|i| format!("?{}", i)).collect();
    let query_sql = format!(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path IN ({})",
        placeholders.join(",")
    );

    // 2. 准备语句
    let mut stmt = vault.database_connection.prepare(&query_sql)?;

    // 3. 执行查询
    let rows = stmt.query_map(params_from_iter(paths), |row| {
        Ok((
            row.get::<_, VaultHash>(0)?,
            row.get::<_, VaultPath>(1)?,
            row.get::<_, VaultHash>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    // 4. 处理结果
    process_rows_to_entries(vault, rows.collect::<Result<Vec<_>, _>>()?)
}

/// 根据文件的 *原始* SHA256 哈希值 (Base64 `&str`) 在保险库中查找文件。
pub(crate) fn check_by_original_hash(
    vault: &Vault,
    original_hash: &VaultHash,
) -> Result<QueryResult, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE original_sha256sum = ?1"
    )?;

    // 参数现在是 *原始* 哈希 (ToSql)
    if let Some(res) = stmt
        .query_row(params![original_hash], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultPath>(1)?,
                row.get::<_, VaultHash>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()?
    {
        // 解构 V2 字段
        let (sha256sum, path, ret_original_sha256sum, encrypt_password) = res;
        // 确认返回的哈希与查询的哈希一致
        assert_eq!(ret_original_sha256sum, *original_hash);

        if !vault.storage.exists(&sha256sum)? {
            return Err(QueryError::FileMissing(sha256sum.to_string()));
        }

        let entry = fetch_full_entry(
            &vault.database_connection,
            &sha256sum,
            path,
            original_hash,
            &encrypt_password,
        )?;
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
pub(crate) fn list_all_files(vault: &Vault) -> Result<Vec<FileEntry>, QueryError> {
    // [修改] 查询 V2 files 表
    let mut stmt = vault
        .database_connection
        .prepare("SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files")?;

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

// 仅列出给定目录路径下的文件和子目录 (非递归)。
// pub(super) fn list_by_path(vault: &Vault, path: &VaultPath) -> Result<Vec<VaultPath>, QueryError> {
//     // 1. 验证输入是否为目录
//     if !path.is_dir() {
//         return Err(QueryError::NotADirectory(path.as_str().to_string()));
//     }
//
//     let mut entries = Vec::new();
//     let mut seen_subdirs = HashSet::new();
//     let base_path_str = path.as_str();
//
//     // 2. 查询所有以该路径为前缀的条目
//     let mut stmt = vault.database_connection.prepare(
//         "SELECT path FROM files WHERE path LIKE ?1",
//     )?;
//     let like_pattern = format!("{}%", base_path_str);
//     let paths_iter = stmt.query_map(params![like_pattern], |row| row.get::<_, String>(0))?;
//
//     for path_result in paths_iter {
//         let file_path_str = path_result?; // file_path_str is String
//         // 3. 计算相对路径
//         let remainder = file_path_str.strip_prefix(base_path_str).unwrap_or("");
//
//         if remainder.contains('/') {
//             // 4. 这是一个子目录或更深层的文件
//             if let Some(subdir_name) = remainder.split('/').next() {
//                 if !subdir_name.is_empty() {
//                     // 我们必须将 subdir_name 作为一个目录段 (带斜杠) 来连接
//                     let subdir_segment = format!("{}/", subdir_name);
//                     let dir_path = path.join(&subdir_segment)?; // 例如 "/".join("docs/")
//
//                     if seen_subdirs.insert(dir_path.clone()) {
//                         entries.push(dir_path);
//                     }
//                 }
//             }
//         } else if !remainder.is_empty() {
//             // 5. 这是一个直属文件
//             // 将 String 转换为 &str 再调用 from
//             entries.push(VaultPath::from(file_path_str.as_str()));
//         }
//     }
//
//     // 6. 排序
//     entries.sort();
//     Ok(entries)
// }

/// 列出给定目录路径下的条目（文件或子目录），如果是文件则返回详细信息。
pub(crate) fn list_by_path(
    vault: &Vault,
    path: &VaultPath,
) -> Result<Vec<DirectoryEntry>, QueryError> {
    // 1. 验证输入是否为目录
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    let mut entries = Vec::new();
    let mut seen_subdirs = HashSet::new();
    let base_path_str = path.as_str();

    // 2. 查询所有以该路径为前缀的条目，同时获取用于构建 FileEntry 的字段
    let mut stmt = vault.database_connection.prepare(
        "SELECT sha256sum, path, original_sha256sum, encrypt_password FROM files WHERE path LIKE ?1",
    )?;
    let like_pattern = format!("{}%", base_path_str);

    // Map 到元组
    let rows = stmt.query_map(params![like_pattern], |row| {
        Ok((
            row.get::<_, VaultHash>(0)?,
            row.get::<_, String>(1)?, // 先读取 path 字符串进行处理
            row.get::<_, VaultHash>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row_result in rows {
        let (sha256sum, file_path_str, original_sha256sum, encrypt_password) = row_result?;

        // 计算相对路径
        let remainder = file_path_str.strip_prefix(base_path_str).unwrap_or("");

        if remainder.contains('/') {
            // 是子目录中的文件
            if let Some(subdir_name) = remainder.split('/').next() {
                if !subdir_name.is_empty() {
                    let subdir_segment = format!("{}/", subdir_name);
                    let dir_path = path.join(&subdir_segment)?;

                    if seen_subdirs.insert(dir_path.clone()) {
                        entries.push(DirectoryEntry::Directory(dir_path));
                    }
                }
            }
        } else if !remainder.is_empty() {
            // 是当前目录下的文件
            let file_vault_path = VaultPath::from(file_path_str.as_str());

            // 获取完整 Entry (包含 tags 和 metadata)
            let file_entry = fetch_full_entry(
                &vault.database_connection,
                &sha256sum,
                file_vault_path,
                &original_sha256sum,
                &encrypt_password,
            )?;

            entries.push(DirectoryEntry::File(file_entry));
        }
    }

    // 3. 排序 (按路径字符串排序)
    entries.sort_by(|a, b| {
        let path_a = match a {
            DirectoryEntry::Directory(p) => p.as_str(),
            DirectoryEntry::File(f) => f.path.as_str(),
        };
        let path_b = match b {
            DirectoryEntry::Directory(p) => p.as_str(),
            DirectoryEntry::File(f) => f.path.as_str(),
        };
        path_a.cmp(path_b)
    });

    Ok(entries)
}

/// 递归列出一个目录下的所有文件 (返回哈希)。
pub(crate) fn list_all_recursive(
    vault: &Vault,
    path: &VaultPath,
) -> Result<Vec<VaultHash>, QueryError> {
    // 1. 验证输入是否为目录
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    // 2. [修正] 查询 sha256sum 字段
    let mut stmt = vault
        .database_connection
        .prepare("SELECT sha256sum FROM files WHERE path LIKE ?1")?;
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

/// 统一的关键字模糊搜索 (不区分大小写)。
pub(crate) fn find_by_keyword(vault: &Vault, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
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
pub(crate) fn get_total_file_count(vault: &Vault) -> Result<i64, QueryError> {
    let count = vault
        .database_connection
        .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))?;
    Ok(count)
}

// 获取所有已启用的扩展功能列表。
pub(crate) fn get_enabled_vault_features(vault: &Vault) -> Result<Vec<String>, QueryError> {
    let mut stmt = vault
        .database_connection
        .prepare("SELECT meta_value FROM vault_metadata WHERE meta_key = ?1")?;

    let result: Option<String> = stmt
        .query_row(params![META_VAULT_FEATURES], |row| row.get(0))
        .optional()?;

    match result {
        Some(features_str) => Ok(features_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()),
        None => Ok(Vec::new()),
    }
}

/// 检查指定的扩展功能是否已启用。
pub(crate) fn is_vault_feature_enabled(
    vault: &Vault,
    feature_name: &str,
) -> Result<bool, QueryError> {
    // 直接查询数据库
    let mut stmt = vault
        .database_connection
        .prepare("SELECT meta_value FROM vault_metadata WHERE meta_key = ?1")?;

    let result: Option<String> = stmt
        .query_row(params![META_VAULT_FEATURES], |row| row.get(0))
        .optional()?;

    match result {
        Some(features_str) => {
            // 分割并检查
            Ok(features_str.split_whitespace().any(|f| f == feature_name))
        }
        None => Ok(false), // 如果元数据不存在，说明没有任何功能被启用
    }
}
