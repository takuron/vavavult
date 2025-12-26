//! Functions for printing vault items to the console.

use crate::core::helpers::parse_rfc3339_string;
use crate::handlers::list::ListResult;
use crate::handlers::vault::VaultStatus;
use crate::ui::formatter::{colorize_string, get_file_color};
use chrono::{DateTime, Local, Utc};
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::DirectoryEntry;

/// 打印递归文件列表中的单个条目 (风格 1)
pub fn print_recursive_file_item(entry: &FileEntry, colors_enabled: bool) {
    let short_hash = &entry.sha256sum.to_string()[..12];

    // 如果启用了颜色且文件有颜色标签，则对整个路径进行着色
    let mut display_path = entry.path.to_string();
    if colors_enabled {
        if let Some(color) = get_file_color(&entry.tags) {
            display_path = colorize_string(&display_path, color);
        }
    }

    // 格式: {12位哈希} {完整路径}
    println!("{:<14} {}", short_hash, display_path);
}

/// 打印目录条目 (用于 ls)
/// 替代旧的 print_shallow_list_item，不再需要查询数据库
pub fn print_directory_entry(entry: &DirectoryEntry, colors_enabled: bool) {
    match entry {
        DirectoryEntry::Directory(path) => {
            // 风格 2: 目录
            // 格式: {占位符} {完整路径}
            println!("--[folder]--   {}", path);
        }
        DirectoryEntry::File(file_entry) => {
            // 风格 1: 文件
            // 直接从 file_entry 获取信息，无需再次查询
            let hash_prefix = &file_entry.sha256sum.to_string()[..12];

            // 处理颜色
            let mut display_path = file_entry.path.to_string();
            if colors_enabled {
                if let Some(color) = get_file_color(&file_entry.tags) {
                    display_path = colorize_string(&display_path, color);
                }
            }

            println!("{:<14} {}", hash_prefix, display_path);
        }
    }
}

/// 打印单个文件的详细信息 (风格 3)
pub fn print_file_details(entry: &FileEntry, colors_enabled: bool) {
    println!("----------------------------------------");

    // 1. 获取颜色 (如果功能开启)
    let color_tag = if colors_enabled {
        get_file_color(&entry.tags)
    } else {
        None
    };

    // 2. 处理文件名显示 (仅对文件名变色)
    let filename = entry.path.file_name().unwrap_or("?");
    let display_name = if let Some(c) = color_tag {
        colorize_string(filename, c)
    } else {
        filename.to_string()
    };

    println!("  Name:            {}", display_name);
    println!("  Type:            File");
    println!("  Path:            {}", entry.path);
    println!("  SHA256 (ID):     {}", entry.sha256sum);
    println!("  Original SHA256: {}", entry.original_sha256sum);

    // [新增] 显示当前颜色名称
    if let Some(c) = color_tag {
        println!("  Color:           {}", c);
    }

    // 过滤掉以 '_' 开头的标签
    let visible_tags: Vec<&str> = entry
        .tags
        .iter()
        .filter(|t| !t.starts_with('_'))
        .map(|t| t.as_str())
        .collect();

    if !visible_tags.is_empty() {
        println!("  Tags:            {}", visible_tags.join(", "));
    }

    // 系统元数据：保留以 _vavavult_ 开头的
    let system_meta: Vec<_> = entry
        .metadata
        .iter()
        .filter(|m| m.key.starts_with("_vavavult_"))
        .collect();

    // 用户元数据：过滤掉所有以 '_' 开头的键
    let user_meta: Vec<_> = entry
        .metadata
        .iter()
        .filter(|m| !m.key.starts_with('_'))
        .collect();

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
                parse_rfc3339_string(&meta.value)
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
}

// --- 风格 4: "详细 目录" (用于 ls -l) ---
/// 打印单个目录的详细信息 (风格 4)
pub fn print_dir_details(path: &VaultPath) {
    if !path.is_dir() {
        return;
    } // 安全检查
    println!("----------------------------------------");
    println!("  Name:    {}", path.dir_name().unwrap_or("/"));
    println!("  Type:    Folder");
    println!("  Path:    {}", path);
}

/// Takes the result from the list handler and prints it to the console.
pub fn print_list_result(
    result: &ListResult,
    long: bool,
    colors_enabled: bool,
    target_path: &VaultPath, // For printing the header
) {
    match result {
        ListResult::Shallow(entries) => {
            if !long {
                println!("Contents of '{}':", target_path);
            }
            if entries.is_empty() {
                println!("(empty)");
                return;
            }
            for entry in entries {
                if long {
                    match entry {
                        DirectoryEntry::Directory(path) => print_dir_details(path),
                        DirectoryEntry::File(file_entry) => {
                            print_file_details(file_entry, colors_enabled)
                        }
                    }
                } else {
                    print_directory_entry(entry, colors_enabled);
                }
            }
            if long && !entries.is_empty() {
                println!("----------------------------------------");
            }
        }
        ListResult::Recursive(all_files) => {
            if !long {
                println!(
                    "Recursively listing contents of '{}' (Files only):",
                    target_path
                );
            }
            if all_files.is_empty() {
                println!("(empty)");
                return;
            }

            for file in all_files {
                if long {
                    print_file_details(file, colors_enabled);
                } else {
                    print_recursive_file_item(file, colors_enabled);
                }
            }
            if long && !all_files.is_empty() {
                println!("----------------------------------------");
            }
        }
    }
}

/// Takes the result from the status handler and prints it to the console.
pub fn print_status(status: &VaultStatus) {
    let features_display = if status.features.is_empty() {
        "None".to_string()
    } else {
        status.features.join(", ")
    };

    let format_time = |time: Option<DateTime<Utc>>| -> String {
        time.map(|utc_time| {
            let local_time = utc_time.with_timezone(&Local);
            local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string()
        })
        .unwrap_or_else(|| "N/A".to_string())
    };

    let create_time_local = format_time(status.created_at);
    let update_time_local = format_time(status.updated_at);

    let encryption_status = if status.encrypted {
        "Enabled"
    } else {
        "Disabled"
    };

    println!("--- Vault Status ---");
    println!("  Name:           {}", status.name);
    println!("  Path:           {:?}", status.path);
    println!("  Version:        {}", status.version);
    println!("  Features:       {}", features_display);
    println!("  Encryption:     {}", encryption_status);
    println!("  Total Files:    {}", status.file_count);
    println!("  Created At:     {}", create_time_local);
    println!("  Last Updated:   {}", update_time_local);
    println!("--------------------");
}
