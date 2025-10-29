use std::error::Error;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use chrono::Local;
use vavavult::common::hash::VaultHash;
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::{QueryResult, Vault};
use vavavult::utils::time as time_utils;

/// 打印 `FileEntry` 列表的辅助函数 (简化版)
pub fn print_file_entries(files: &[FileEntry]) {
    if files.is_empty() {
        return;
    }
    for entry in files {
        let short_hash = &entry.sha256sum.to_string()[..12];
        println!("{:<14} {}", short_hash, entry.path);
    }
}

/// 打印单个文件详细信息的辅助函数
pub fn print_file_details(entry: &FileEntry) {
    println!("----------------------------------------");
    println!("  Name:    {}", entry.path);
    println!("  SHA256:  {}", entry.sha256sum);

    // 打印标签，如果存在
    if !entry.tags.is_empty() {
        println!("  Tags:    {}", entry.tags.join(", "));
    }

    // 筛选并打印元数据
    let system_meta: Vec<_> = entry.metadata.iter().filter(|m| m.key.starts_with("_vavavult_")).collect();
    let user_meta: Vec<_> = entry.metadata.iter().filter(|m| !m.key.starts_with("_vavavult_")).collect();

    if !user_meta.is_empty() {
        println!("  Metadata:");
        for meta in user_meta {
            println!("    - {}: {}", meta.key, meta.value);
        }
    }

    if !system_meta.is_empty() {
        println!("  System Info:");
        for meta in system_meta {
            // 美化键名
            let pretty_key = meta.key.trim_start_matches("_vavavult_").replace('_', " ");

            // --- 新增逻辑：检查是否是时间戳并进行转换 ---
            let value = if meta.key.ends_with("_time") {
                // 如果元数据的键以 "_time" 结尾，就尝试解析并格式化为本地时间
                time_utils::parse_rfc3339_string(&meta.value)
                    .map(|utc_time| {
                        let local_time = utc_time.with_timezone(&Local);
                        local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string()
                    })
                    .unwrap_or_else(|_| meta.value.clone()) // 如果解析失败，则显示原始值
            } else {
                // 否则，直接使用原始值
                meta.value.clone()
            };
            // --- 逻辑结束 ---

            println!("    - {}: {}", pretty_key, value);
        }
    }
}


// --- 新增: 辅助函数 ---

/// 根据 name 或 sha256 查找文件，返回找到的 FileEntry
pub fn find_file_entry(vault: &Vault, name: Option<String>, sha: Option<String>) -> Result<FileEntry, Box<dyn Error>> {
    let query_result = if let Some(n) = name {
        // [修改] 使用 find_by_path 和 VaultPath
        vault.find_by_path(&VaultPath::from(n.as_str()))?
    } else if let Some(s) = sha {
        // [修改] 使用 find_by_hash 和 VaultHash
        let hash = VaultHash::from_str(&s)?;
        vault.find_by_hash(&hash)?
    } else {
        unreachable!(); // Clap 应该已经阻止了这种情况
    };

    match query_result {
        QueryResult::Found(entry) => Ok(entry),
        QueryResult::NotFound => Err("File not found in the vault.".into()),
    }
}

/// 确定最终的输出路径
pub fn determine_output_path(entry: &FileEntry, dest_dir: PathBuf, output_name: Option<String>) -> PathBuf {
    let final_filename = output_name.unwrap_or_else(|| {
        Path::new(&entry.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed_file")
            .to_string()
    });
    dest_dir.join(final_filename)
}

/// 向用户请求确认破坏性操作
pub fn confirm_action(prompt: &str) -> Result<bool, io::Error> {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    Ok(confirmation.trim().eq_ignore_ascii_case("y") || confirmation.trim().eq_ignore_ascii_case("yes"))
}

/// 打印 `ListResult` 的辅助函数
pub fn print_list_result(paths: &[VaultPath]) {
    if paths.is_empty() {
        println!("(empty)");
        return;
    }

    // 1. 分离文件和目录
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for path in paths {
        if path.is_dir() {
            dirs.push(path);
        } else {
            files.push(path);
        }
    }

    // 2. 先打印目录
    for dir_path in dirs {
        // 从 "/a/b/c/" 中提取 "c"
        let dir_name = dir_path.dir_name().unwrap_or("?");
        println!("[{}/]", dir_name);
    }

    // 3. 再打印文件 (仅路径)
    for file_path in files {
        // 从 "/a/b/c.txt" 中提取 "c.txt"
        let file_name = file_path.file_name().unwrap_or("?");
        // 打印简化的输出，不带哈希
        println!("  {}", file_name);
    }
}

/// 递归地获取一个 vault 目录下的所有文件
pub(crate) fn get_all_files_recursively(vault: &Vault, dir_path: &str) -> Result<Vec<FileEntry>, Box<dyn Error>> {

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