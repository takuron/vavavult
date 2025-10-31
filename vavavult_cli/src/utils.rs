use std::error::Error;
use std::io;
use std::io::Write;
use std::path::{PathBuf};
use std::str::FromStr;
use chrono::Local;
use vavavult::common::hash::VaultHash;
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::{QueryResult, Vault};
use vavavult::utils::time as time_utils;

/// 打印递归文件列表中的单个条目 (风格 1)
pub fn print_recursive_file_item(entry: &FileEntry) {
    let short_hash = &entry.sha256sum.to_string()[..12];
    // 格式: {12位哈希} {完整路径}
    println!("{:<14} {}", short_hash, entry.path);
}

/// 打印浅层(非递归)列表中的单个条目 (风格 1+2 混合)
/// 注意：此函数效率较低，因为它需要为每个文件查询数据库以获取哈希值。
pub fn print_shallow_list_item(path: &VaultPath, vault: &Vault) {
    if path.is_dir() {
        // 风格 2: 目录
        // 格式: {占位符} {完整路径}
        println!("--[folder]--   {}", path);
    } else {
        // 风格 1: 文件
        // 我们需要获取 FileEntry 来显示哈希
        let hash_prefix = match vault.find_by_path(path) {
            Ok(QueryResult::Found(entry)) => entry.sha256sum.to_string()[..12].to_string(),
            _ => "??[error]??".to_string(), // 如果查询失败
        };
        println!("{:<14} {}", hash_prefix, path);
    }
}

/// 打印单个文件的详细信息 (风格 3)
pub fn print_file_details(entry: &FileEntry) {
    println!("----------------------------------------");
    // [V2 新增] 匹配您的新格式
    println!("  Name:    {}", entry.path.file_name().unwrap_or("?"));
    println!("  Type:    File");
    println!("  Path:    {}", entry.path);
    println!("  SHA256:  {}", entry.sha256sum);

    // (保留旧逻辑中的 标签 和 元数据，因为它们是详细信息的重要组成部分)
    if !entry.tags.is_empty() {
        println!("  Tags:    {}", entry.tags.join(", "));
    }

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
            let pretty_key = meta.key.trim_start_matches("_vavavult_").replace('_', " ");
            let value = if meta.key.ends_with("_time") {
                time_utils::parse_rfc3339_string(&meta.value)
                    .map(|utc_time| {
                        let local_time = utc_time.with_timezone(&Local);
                        local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string()
                    })
                    .unwrap_or_else(|_| meta.value.clone())
            } else {
                meta.value.clone()
            };
            println!("    - {}: {}", pretty_key, value);
        }
    }
    // (结尾的横线由 list handler 统一添加)
}

// --- [V2 新增] 风格 4: "详细 目录" (用于 ls -l) ---
/// 打印单个目录的详细信息 (风格 4)
pub fn print_dir_details(path: &VaultPath) {
    if !path.is_dir() { return; } // 安全检查
    println!("----------------------------------------");
    println!("  Name:    {}", path.dir_name().unwrap_or("/"));
    println!("  Type:    Folder");
    println!("  Path:    {}", path);
}

// --- 辅助函数 ---

/// 根据 path 或 hash 查找文件，返回找到的 FileEntry
pub fn find_file_entry(
    vault: &Vault,
    path: Option<String>,
    hash: Option<String>,
) -> Result<FileEntry, Box<dyn Error>> {
    let query_result = if let Some(p) = path {
        // 按路径查找
        vault.find_by_path(&VaultPath::from(p.as_str()))?
    } else if let Some(h) = hash {
        // 按哈希查找
        let vault_hash = VaultHash::from_str(&h)?;
        vault.find_by_hash(&vault_hash)?
    } else {
        // 适应新的参数名
        return Err("You must provide either a --path (-p) or a --hash (-h).".into());
    };

    match query_result {
        QueryResult::Found(entry) => Ok(entry),
        QueryResult::NotFound => Err("File not found in the vault.".into()),
    }
}

/// 确定最终的输出路径
pub fn determine_output_path(entry: &FileEntry, dest_dir: PathBuf, output_name: Option<String>) -> PathBuf {
    let final_filename = output_name.unwrap_or_else(|| {
        // [修改] 使用 VaultPath::file_name() 代替 Path::new()
        entry.path.file_name()
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
// pub fn print_list_result(paths: &[VaultPath]) {
//     if paths.is_empty() {
//         println!("(empty)");
//         return;
//     }
//
//     // 1. 分离文件和目录
//     let mut files = Vec::new();
//     let mut dirs = Vec::new();
//     for path in paths {
//         if path.is_dir() {
//             dirs.push(path);
//         } else {
//             files.push(path);
//         }
//     }
//
//     // 2. 先打印目录
//     for dir_path in dirs {
//         // 从 "/a/b/c/" 中提取 "c"
//         let dir_name = dir_path.dir_name().unwrap_or("?");
//         println!("[{}/]", dir_name);
//     }
//
//     // 3. 再打印文件 (仅路径)
//     for file_path in files {
//         // 从 "/a/b/c.txt" 中提取 "c.txt"
//         let file_name = file_path.file_name().unwrap_or("?");
//         // 打印简化的输出，不带哈希
//         println!("  {}", file_name);
//     }
// }

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