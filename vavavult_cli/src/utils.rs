use std::error::Error;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use chrono::Local;
use vavavult::file::FileEntry;
use vavavult::vault::{ListResult, QueryResult, Vault};
use vavavult::utils::time as time_utils;

/// 打印 `FileEntry` 列表的辅助函数 (简化版)
pub fn print_file_entries(files: &[FileEntry]) {
    if files.is_empty() {
        return;
    }
    // 彻底移除表头
    for entry in files {
        let short_hash = &entry.sha256sum[..12];
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
        vault.find_by_name(&n)?
    } else if let Some(s) = sha {
        vault.find_by_hash(&s)?
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
pub fn print_list_result(result: &ListResult) {
    if result.subdirectories.is_empty() && result.files.is_empty() {
        println!("(empty)");
        return;
    }
    // 先打印目录
    for dir in &result.subdirectories {
        println!("[{}/]", dir);
    }
    // 再打印文件
    print_file_entries(&result.files);
}

/// 递归地获取一个 vault 目录下的所有文件
pub(crate) fn get_all_files_recursively(vault: &Vault, dir_path: &str) -> Result<Vec<FileEntry>, Box<dyn Error>> {
    let mut all_files = Vec::new();
    let mut dirs_to_scan = vec![dir_path.to_string()];

    while let Some(current_dir) = dirs_to_scan.pop() {
        let result = vault.list_by_path(&current_dir)?;
        all_files.extend(result.files);
        for subdir in result.subdirectories {
            let full_subdir_path = Path::new(&current_dir).join(subdir).to_string_lossy().into_owned();
            dirs_to_scan.push(full_subdir_path);
        }
    }
    Ok(all_files)
}