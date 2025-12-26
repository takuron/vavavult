//! Core business logic helpers, independent of UI.

use crate::errors::CliError;
use chrono::{DateTime, ParseError, Utc};
use std::path::PathBuf;
use std::str::FromStr;
use vavavult::common::hash::VaultHash;
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::{QueryResult, Vault};

// 本地辅助函数：解析 RFC 3339 字符串
pub fn parse_rfc3339_string(s: &str) -> Result<DateTime<Utc>, ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

// 目标类型枚举
#[derive(Debug)]
pub enum Target {
    Path(VaultPath),
    Hash(VaultHash),
}

/// 根据字符串格式自动推断目标类型
/// 规则：
/// 1. 以 '/' 开头 -> 路径 (Path)
/// 2. 长度为 43 -> 哈希 (Hash)
/// 3. 其他 -> 错误
pub fn identify_target(target: &str) -> Result<Target, CliError> {
    if target.starts_with('/') {
        Ok(Target::Path(VaultPath::from(target)))
    } else if target.len() == VaultHash::BASE64_LEN && !target.contains('/') {
        // 尝试解析哈希以验证字符合法性
        match VaultHash::from_str(target) {
            Ok(h) => Ok(Target::Hash(h)),
            Err(e) => Err(CliError::InvalidHashFormat(e.to_string())),
        }
    } else {
        Err(CliError::InvalidTarget(format!(
            "Target '{}' is not a valid format. It must start with '/' for an absolute path or be a {} character hash.",
            target,
            VaultHash::BASE64_LEN
        )))
    }
}

/// 查找文件条目，自动推断目标类型
/// 用于期望找到单个文件的情况 (如 Open, Rename)
pub fn find_file_entry(vault: &Vault, target: &str) -> Result<FileEntry, CliError> {
    match identify_target(target)? {
        Target::Path(p) => {
            // 如果是路径，查询数据库
            match vault.find_by_path(&p)? {
                QueryResult::Found(entry) => Ok(entry),
                QueryResult::NotFound => Err(CliError::EntryNotFound(format!(
                    "File not found at path '{}'.",
                    p
                ))),
            }
        }
        Target::Hash(h) => {
            // 如果是哈希，查询数据库
            match vault.find_by_hash(&h)? {
                QueryResult::Found(entry) => Ok(entry),
                QueryResult::NotFound => Err(CliError::EntryNotFound(format!(
                    "File not found with hash '{}'.",
                    h
                ))),
            }
        }
    }
}

/// 确定最终的输出路径
pub fn determine_output_path(
    entry: &FileEntry,
    dest_dir: PathBuf,
    output_name: Option<String>,
) -> PathBuf {
    let final_filename = output_name.unwrap_or_else(|| {
        // [修改] 使用 VaultPath::file_name() 代替 Path::new()
        entry.path.file_name().unwrap_or("unnamed_file").to_string()
    });
    dest_dir.join(final_filename)
}

/// 递归地获取一个 vault 目录下的所有文件
pub fn get_all_files_recursively(
    vault: &Vault,
    dir_path: &str,
) -> Result<Vec<FileEntry>, CliError> {
    // 1. [修改] 将字符串路径转换为 VaultPath
    let dir_vault_path = VaultPath::from(dir_path);
    if !dir_vault_path.is_dir() {
        // 如果用户传入了文件路径，则只返回该文件
        return match vault.find_by_path(&dir_vault_path)? {
            QueryResult::Found(entry) => Ok(vec![entry]),
            QueryResult::NotFound => Ok(Vec::new()),
        };
    }

    // 2. [修改] 调用新的 `list_all_recursive` API 获取哈希列表
    let hashes = vault.list_all_recursive(&dir_vault_path)?;

    // 3. [修改] 遍历哈希，查找完整的 FileEntry
    let mut all_files = Vec::new();
    for hash in hashes {
        match vault.find_by_hash(&hash)? {
            QueryResult::Found(entry) => all_files.push(entry),
            QueryResult::NotFound => {
                // 数据库不一致，但我们暂时忽略
            }
        }
    }
    Ok(all_files)
}

/// A simple heuristic to check if a string looks like a hash.
//
// // 一个简单的启发式方法，用于检查字符串是否看起来像一个哈希。
pub fn is_hash_like(s: &str) -> bool {
    s.len() == VaultHash::BASE64_LEN && !s.contains('/')
}
