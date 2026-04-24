use crate::common::constants::META_VAULT_FEATURES;
use crate::common::hash::{HashParseError, VaultHash};
use crate::common::metadata::MetadataEntry;
use crate::file::{FileEntry, PathError, VaultPath};
use crate::vault::Vault;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};

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
    /// A file entry, containing full details (hash, metadata, tags, etc.).
    // // 文件条目，包含完整详细信息（哈希、元数据、标签等）。
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

fn directory_components(path: &VaultPath) -> Result<Vec<&str>, QueryError> {
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    Ok(path
        .as_str()
        .trim_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect())
}

/// 解析目录路径，返回对应的目录 ID。
pub(crate) fn resolve_directory_in_conn(
    conn: &Connection,
    path: &VaultPath,
) -> Result<Option<i64>, QueryError> {
    let components = directory_components(path)?;

    // 根目录是固定挂载点，但仍通过数据库读取以捕获损坏的 schema。
    let mut current_id = match conn
        .query_row(
            "SELECT id FROM directories WHERE parent_id IS NULL AND name = ''",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    {
        Some(id) => id,
        None => return Ok(None),
    };

    for component in components {
        let next_id = conn
            .query_row(
                "SELECT id FROM directories WHERE parent_id = ?1 AND name = ?2",
                params![current_id, component],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        match next_id {
            Some(id) => current_id = id,
            None => return Ok(None),
        }
    }

    Ok(Some(current_id))
}

/// 解析目录路径，返回对应的目录 ID。
pub(crate) fn resolve_directory(
    vault: &Vault,
    path: &VaultPath,
) -> Result<Option<i64>, QueryError> {
    resolve_directory_in_conn(&vault.database_connection, path)
}

/// 创建缺失的目录层级，并返回最终目录 ID。
pub(crate) fn ensure_directory_in_conn(
    conn: &Connection,
    path: &VaultPath,
) -> Result<i64, QueryError> {
    let components = directory_components(path)?;

    let mut current_id = conn.query_row(
        "SELECT id FROM directories WHERE parent_id IS NULL AND name = ''",
        [],
        |row| row.get::<_, i64>(0),
    )?;

    for component in components {
        let existing_id = conn
            .query_row(
                "SELECT id FROM directories WHERE parent_id = ?1 AND name = ?2",
                params![current_id, component],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        current_id = match existing_id {
            Some(id) => id,
            None => {
                conn.execute(
                    "INSERT INTO directories (parent_id, name) VALUES (?1, ?2)",
                    params![current_id, component],
                )?;
                conn.last_insert_rowid()
            }
        };
    }

    Ok(current_id)
}

/// 在指定路径插入文件映射。
pub(crate) fn insert_file_entry_in_conn(
    conn: &Connection,
    path: &VaultPath,
    file_sha256sum: &VaultHash,
) -> Result<(), QueryError> {
    let parent_path = path.parent()?;
    let directory_id = ensure_directory_in_conn(conn, &parent_path)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| QueryError::NotADirectory(path.as_str().to_string()))?;

    conn.execute(
        "INSERT INTO file_entries (directory_id, name, file_sha256sum) VALUES (?1, ?2, ?3)",
        params![directory_id, file_name, file_sha256sum],
    )?;

    Ok(())
}

/// 删除指定路径上的文件映射，并返回它指向的文件哈希。
pub(crate) fn remove_file_entry_by_path_in_conn(
    conn: &Connection,
    path: &VaultPath,
) -> Result<Option<VaultHash>, QueryError> {
    if !path.is_file() {
        return Ok(None);
    }

    let parent_path = path.parent()?;
    let Some(directory_id) = resolve_directory_in_conn(conn, &parent_path)? else {
        return Ok(None);
    };
    let Some(file_name) = path.file_name() else {
        return Ok(None);
    };

    let row = conn
        .query_row(
            "SELECT id, file_sha256sum FROM file_entries WHERE directory_id = ?1 AND name = ?2",
            params![directory_id, file_name],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, VaultHash>(1)?)),
        )
        .optional()?;

    if let Some((entry_id, file_sha256sum)) = row {
        conn.execute("DELETE FROM file_entries WHERE id = ?1", params![entry_id])?;
        Ok(Some(file_sha256sum))
    } else {
        Ok(None)
    }
}

/// 删除指定哈希的一条文件映射，并返回是否删除了映射。
pub(crate) fn remove_first_file_entry_by_hash_in_conn(
    conn: &Connection,
    hash: &VaultHash,
) -> Result<bool, QueryError> {
    let rows = conn.execute(
        "DELETE FROM file_entries
         WHERE id = (
             SELECT id FROM file_entries WHERE file_sha256sum = ?1 ORDER BY id LIMIT 1
         )",
        params![hash],
    )?;

    Ok(rows > 0)
}

/// 统计指定文件实体当前仍被多少路径映射引用。
pub(crate) fn file_entry_ref_count_in_conn(
    conn: &Connection,
    hash: &VaultHash,
) -> Result<i64, QueryError> {
    let count = conn.query_row(
        "SELECT COUNT(*) FROM file_entries WHERE file_sha256sum = ?1",
        params![hash],
        |row| row.get::<_, i64>(0),
    )?;

    Ok(count)
}

fn fetch_file_core_by_path(
    conn: &Connection,
    path: &VaultPath,
) -> Result<Option<(VaultHash, VaultHash, String)>, QueryError> {
    if !path.is_file() {
        return Ok(None);
    }

    let parent_path = path.parent()?;
    let Some(directory_id) = resolve_directory_in_conn(conn, &parent_path)? else {
        return Ok(None);
    };
    let Some(file_name) = path.file_name() else {
        return Ok(None);
    };

    let row = conn
        .query_row(
            "SELECT f.sha256sum, f.original_sha256sum, f.encrypt_password
             FROM file_entries fe
             JOIN files f ON f.sha256sum = fe.file_sha256sum
             WHERE fe.directory_id = ?1 AND fe.name = ?2",
            params![directory_id, file_name],
            |row| {
                Ok((
                    row.get::<_, VaultHash>(0)?,
                    row.get::<_, VaultHash>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;

    Ok(row)
}

/// 一个内部辅助函数，用于从数据库中获取一个文件的完整信息。
pub(crate) fn fetch_full_entry(
    conn: &Connection,
    sha256sum: &VaultHash,
    original_sha256sum: &VaultHash,
    encrypt_password: &str,
) -> Result<FileEntry, QueryError> {
    // 查询标签。
    let mut tags_stmt = conn.prepare("SELECT tag FROM tags WHERE file_sha256sum = ?1")?;
    let tags = tags_stmt
        .query_map(params![sha256sum], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    // 查询元数据。
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

    Ok(FileEntry {
        sha256sum: sha256sum.clone(),
        original_sha256sum: original_sha256sum.clone(),
        encrypt_password: encrypt_password.to_string(),
        tags,
        metadata,
    })
}

fn fetch_full_entry_from_core(
    vault: &Vault,
    sha256sum: &VaultHash,
    original_sha256sum: &VaultHash,
    encrypt_password: &str,
    validate_storage: bool,
) -> Result<FileEntry, QueryError> {
    if validate_storage && !vault.storage.exists(sha256sum)? {
        return Err(QueryError::FileMissing(sha256sum.to_string()));
    }

    fetch_full_entry(
        &vault.database_connection,
        sha256sum,
        original_sha256sum,
        encrypt_password,
    )
}

/// 根据文件路径在保险库中查找文件。
pub(crate) fn check_by_path(vault: &Vault, path: &VaultPath) -> Result<QueryResult, QueryError> {
    match fetch_file_core_by_path(&vault.database_connection, path)? {
        Some((sha256sum, original_sha256sum, encrypt_password)) => {
            let entry = fetch_full_entry_from_core(
                vault,
                &sha256sum,
                &original_sha256sum,
                &encrypt_password,
                true,
            )?;
            Ok(QueryResult::Found(entry))
        }
        None => Ok(QueryResult::NotFound),
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
    match fetch_file_core_by_path(&vault.database_connection, path)? {
        Some((sha256sum, original_sha256sum, encrypt_password)) => {
            Ok(QueryResult::Found(fetch_full_entry_from_core(
                vault,
                &sha256sum,
                &original_sha256sum,
                &encrypt_password,
                false,
            )?))
        }
        None => Ok(QueryResult::NotFound),
    }
}

fn fetch_file_core_by_hash(
    vault: &Vault,
    hash: &VaultHash,
    validate_storage: bool,
) -> Result<QueryResult, QueryError> {
    let row = vault
        .database_connection
        .query_row(
            "SELECT sha256sum, original_sha256sum, encrypt_password FROM files WHERE sha256sum = ?1",
            params![hash],
            |row| {
                Ok((
                    row.get::<_, VaultHash>(0)?,
                    row.get::<_, VaultHash>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;

    match row {
        Some((ret_sha256sum, original_sha256sum, encrypt_password)) => {
            assert_eq!(ret_sha256sum, *hash);
            let entry = fetch_full_entry_from_core(
                vault,
                hash,
                &original_sha256sum,
                &encrypt_password,
                validate_storage,
            )?;
            Ok(QueryResult::Found(entry))
        }
        None => Ok(QueryResult::NotFound),
    }
}

/// A variant of `check_by_hash` that does not validate physical file existence.
#[allow(dead_code)]
pub(crate) fn check_by_hash_no_validation(
    vault: &Vault,
    hash: &VaultHash,
) -> Result<QueryResult, QueryError> {
    fetch_file_core_by_hash(vault, hash, false)
}

/// 根据文件的加密后 SHA256 哈希值在保险库中查找文件。
pub(crate) fn check_by_hash(vault: &Vault, hash: &VaultHash) -> Result<QueryResult, QueryError> {
    fetch_file_core_by_hash(vault, hash, true)
}

/// 列出指定文件哈希对应的所有保险库路径。
pub(crate) fn list_paths_by_hash_in_conn(
    conn: &Connection,
    hash: &VaultHash,
) -> Result<Vec<VaultPath>, QueryError> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE entry_paths(file_entry_id, path, parent_id) AS (
             SELECT fe.id,
                    CASE WHEN d.parent_id IS NULL THEN fe.name ELSE d.name || '/' || fe.name END,
                    d.parent_id
             FROM file_entries fe
             JOIN directories d ON d.id = fe.directory_id
             WHERE fe.file_sha256sum = ?1
             UNION ALL
             SELECT ep.file_entry_id,
                    CASE WHEN parent.parent_id IS NULL THEN ep.path ELSE parent.name || '/' || ep.path END,
                    parent.parent_id
             FROM entry_paths ep
             JOIN directories parent ON parent.id = ep.parent_id
         )
         SELECT '/' || path FROM entry_paths WHERE parent_id IS NULL ORDER BY path",
    )?;

    let paths = stmt
        .query_map(params![hash], |row| row.get::<_, VaultPath>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(paths)
}

/// 列出指定文件哈希对应的所有保险库路径。
pub(crate) fn list_paths_by_hash(
    vault: &Vault,
    hash: &VaultHash,
) -> Result<Vec<VaultPath>, QueryError> {
    list_paths_by_hash_in_conn(&vault.database_connection, hash)
}

/// 批量根据哈希查找文件。
pub(crate) fn find_by_hashes(
    vault: &Vault,
    hashes: &[VaultHash],
) -> Result<Vec<FileEntry>, QueryError> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders: Vec<String> = (1..=hashes.len()).map(|i| format!("?{}", i)).collect();
    let query_sql = format!(
        "SELECT sha256sum, original_sha256sum, encrypt_password FROM files WHERE sha256sum IN ({})",
        placeholders.join(",")
    );
    let mut stmt = vault.database_connection.prepare(&query_sql)?;
    let rows = stmt
        .query_map(params_from_iter(hashes), |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultHash>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// 批量根据路径查找文件。
pub(crate) fn find_by_paths(
    vault: &Vault,
    paths: &[VaultPath],
) -> Result<Vec<FileEntry>, QueryError> {
    let mut entries = Vec::new();

    for path in paths {
        if let QueryResult::Found(entry) = check_by_path(vault, path)? {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// 根据文件的原始 SHA256 哈希值在保险库中查找文件。
pub(crate) fn check_by_original_hash(
    vault: &Vault,
    original_hash: &VaultHash,
) -> Result<QueryResult, QueryError> {
    let row = vault
        .database_connection
        .query_row(
            "SELECT sha256sum, original_sha256sum, encrypt_password FROM files WHERE original_sha256sum = ?1",
            params![original_hash],
            |row| {
                Ok((
                    row.get::<_, VaultHash>(0)?,
                    row.get::<_, VaultHash>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;

    match row {
        Some((sha256sum, ret_original_sha256sum, encrypt_password)) => {
            assert_eq!(ret_original_sha256sum, *original_hash);
            let entry = fetch_full_entry_from_core(
                vault,
                &sha256sum,
                original_hash,
                &encrypt_password,
                true,
            )?;
            Ok(QueryResult::Found(entry))
        }
        None => Ok(QueryResult::NotFound),
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

fn process_rows_to_entries(
    vault: &Vault,
    rows: Vec<(VaultHash, VaultHash, String)>,
) -> Result<Vec<FileEntry>, QueryError> {
    let mut entries = Vec::with_capacity(rows.len());

    for (sha256sum, original_sha256sum, encrypt_password) in rows {
        let entry = fetch_full_entry_from_core(
            vault,
            &sha256sum,
            &original_sha256sum,
            &encrypt_password,
            true,
        )?;
        entries.push(entry);
    }

    Ok(entries)
}

/// 列出保险库中的所有文件实体。
pub(crate) fn list_all_files(vault: &Vault) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault
        .database_connection
        .prepare("SELECT sha256sum, original_sha256sum, encrypt_password FROM files")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultHash>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// 列出给定目录路径下的条目（文件或子目录）。
pub(crate) fn list_by_path(
    vault: &Vault,
    path: &VaultPath,
) -> Result<Vec<DirectoryEntry>, QueryError> {
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    let Some(directory_id) = resolve_directory(vault, path)? else {
        return Ok(Vec::new());
    };

    let mut entries = Vec::new();

    // 先读取子目录，构造完整目录路径。
    let mut dir_stmt = vault
        .database_connection
        .prepare("SELECT name FROM directories WHERE parent_id = ?1 ORDER BY name")?;
    let dir_names = dir_stmt
        .query_map(params![directory_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    for dir_name in dir_names {
        entries.push(DirectoryEntry::Directory(
            path.join(&format!("{}/", dir_name))?,
        ));
    }

    // 再读取直属文件映射。
    let mut file_stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.original_sha256sum, f.encrypt_password
         FROM file_entries fe
         JOIN files f ON f.sha256sum = fe.file_sha256sum
         WHERE fe.directory_id = ?1
         ORDER BY fe.name",
    )?;
    let file_rows = file_stmt
        .query_map(params![directory_id], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultHash>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for file_entry in process_rows_to_entries(vault, file_rows)? {
        entries.push(DirectoryEntry::File(file_entry));
    }

    Ok(entries)
}

/// 递归列出一个目录下的所有文件实体哈希。
pub(crate) fn list_all_recursive(
    vault: &Vault,
    path: &VaultPath,
) -> Result<Vec<VaultHash>, QueryError> {
    if !path.is_dir() {
        return Err(QueryError::NotADirectory(path.as_str().to_string()));
    }

    let Some(directory_id) = resolve_directory(vault, path)? else {
        return Ok(Vec::new());
    };

    let mut stmt = vault.database_connection.prepare(
        "WITH RECURSIVE subtree(id) AS (
             SELECT ?1
             UNION ALL
             SELECT d.id FROM directories d JOIN subtree s ON d.parent_id = s.id
         )
         SELECT DISTINCT fe.file_sha256sum
         FROM file_entries fe
         JOIN subtree s ON fe.directory_id = s.id
         ORDER BY fe.file_sha256sum",
    )?;

    let hashes = stmt
        .query_map(params![directory_id], |row| row.get::<_, VaultHash>(0))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(hashes)
}

/// 按特定标签查找文件。
pub fn find_by_tag(vault: &Vault, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
    let mut stmt = vault.database_connection.prepare(
        "SELECT f.sha256sum, f.original_sha256sum, f.encrypt_password
         FROM files f JOIN tags t ON f.sha256sum = t.file_sha256sum
         WHERE t.tag = ?1",
    )?;

    let rows = stmt
        .query_map(params![tag], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultHash>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// 统一的关键字模糊搜索 (不区分大小写)。
pub(crate) fn find_by_keyword(vault: &Vault, keyword: &str) -> Result<Vec<FileEntry>, QueryError> {
    let like_pattern = format!("%{}%", keyword.to_lowercase());

    let mut stmt = vault.database_connection.prepare(
        "WITH RECURSIVE entry_paths(file_entry_id, file_sha256sum, path, parent_id) AS (
             SELECT fe.id,
                    fe.file_sha256sum,
                    CASE WHEN d.parent_id IS NULL THEN fe.name ELSE d.name || '/' || fe.name END,
                    d.parent_id
             FROM file_entries fe
             JOIN directories d ON d.id = fe.directory_id
             UNION ALL
             SELECT ep.file_entry_id,
                    ep.file_sha256sum,
                    CASE WHEN parent.parent_id IS NULL THEN ep.path ELSE parent.name || '/' || ep.path END,
                    parent.parent_id
             FROM entry_paths ep
             JOIN directories parent ON parent.id = ep.parent_id
         )
         SELECT DISTINCT f.sha256sum, f.original_sha256sum, f.encrypt_password
         FROM files f
         LEFT JOIN tags t ON f.sha256sum = t.file_sha256sum
         LEFT JOIN entry_paths ep ON f.sha256sum = ep.file_sha256sum AND ep.parent_id IS NULL
         WHERE LOWER('/' || ep.path) LIKE ?1 OR LOWER(t.tag) LIKE ?1",
    )?;

    let rows = stmt
        .query_map(params![like_pattern], |row| {
            Ok((
                row.get::<_, VaultHash>(0)?,
                row.get::<_, VaultHash>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    process_rows_to_entries(vault, rows)
}

/// 高效地获取保险库中文件实体的总数。
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
    let mut stmt = vault
        .database_connection
        .prepare("SELECT meta_value FROM vault_metadata WHERE meta_key = ?1")?;

    let result: Option<String> = stmt
        .query_row(params![META_VAULT_FEATURES], |row| row.get(0))
        .optional()?;

    match result {
        Some(features_str) => Ok(features_str.split_whitespace().any(|f| f == feature_name)),
        None => Ok(false),
    }
}
