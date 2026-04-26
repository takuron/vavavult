//! Functions for printing vault items to the console.

use crate::core::helpers::parse_rfc3339_string;
use crate::handlers::list::ListResult;
use crate::handlers::vault::VaultStatus;
use crate::ui::formatter::{colorize_string, get_file_color};
use chrono::{DateTime, Local, Utc};
use std::collections::HashSet;
use vavavult::file::VaultPath;
use vavavult::vault::{DirectoryEntry, FilePathEntry, ListPathEntry, QueryFileResult, Vault};

/// 打印递归文件列表中的单个条目 (风格 1)
pub fn print_recursive_file_item(_vault: &Vault, entry: &FilePathEntry, colors_enabled: bool) {
    let hash_string = entry.sha256sum.to_string();
    let short_hash = &hash_string[..12];

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

/// 打印路径化文件列表中的单个条目。
pub fn print_file_path_item(_vault: &Vault, entry: &FilePathEntry, colors_enabled: bool) {
    let hash_string = entry.sha256sum.to_string();
    let short_hash = &hash_string[..12];

    // 如果启用了颜色且文件有颜色标签，则加载标签并对路径着色。
    let mut display_path = entry.path.to_string();
    if colors_enabled && let Some(color) = get_file_color(&entry.tags) {
        display_path = colorize_string(&display_path, color);
    }

    println!("{:<14} {}", short_hash, display_path);
}

/// 打印目录条目 (用于 ls)
/// 替代旧的 print_shallow_list_item，不再需要查询数据库
pub fn print_directory_entry(_vault: &Vault, entry: &ListPathEntry, colors_enabled: bool) {
    match entry {
        ListPathEntry::Directory(directory_entry) => {
            // 风格 2: 目录
            // 格式: {占位符} {完整路径}
            println!("--[folder]--   {}", directory_entry.path);
        }
        ListPathEntry::File(file_path_entry) => {
            // 风格 1: 文件
            // 直接使用路径列表返回的路径和哈希。
            let hash_string = file_path_entry.sha256sum.to_string();
            let hash_prefix = &hash_string[..12];

            // 处理颜色
            let mut display_path = file_path_entry.path.to_string();
            if colors_enabled && let Some(color) = get_file_color(&file_path_entry.tags) {
                display_path = colorize_string(&display_path, color);
            }

            println!("{:<14} {}", hash_prefix, display_path);
        }
    }
}

/// 打印单个文件的详细信息 (风格 3)
pub fn print_file_details(vault: &Vault, path_entry: &FilePathEntry, colors_enabled: bool) {
    print_file_details_with_paths(vault, path_entry, &[path_entry], colors_enabled);
}

/// 打印单个文件实体及其路径映射的详细信息 (风格 3)。
fn print_file_details_with_paths(
    vault: &Vault,
    path_entry: &FilePathEntry,
    path_entries: &[&FilePathEntry],
    colors_enabled: bool,
) {
    println!("----------------------------------------");

    let file_entry = match vault.find_by_hash(&path_entry.sha256sum) {
        Ok(QueryFileResult::Found(file_entry)) => Some(file_entry),
        _ => None,
    };

    // 1. 使用第一个路径映射作为文件名展示来源。
    let filename = path_entry
        .path
        .file_name()
        .map(str::to_string)
        .unwrap_or_else(|| path_entry.sha256sum.to_string());

    // 2. 如果启用颜色，则用第一个路径映射的颜色标签渲染文件名。
    let display_name = if colors_enabled && let Some(c) = get_file_color(&path_entry.tags) {
        colorize_string(&filename, c)
    } else {
        filename
    };

    println!("  Name:            {}", display_name);
    println!("  Type:            File");
    println!("  Paths:");
    for entry in path_entries {
        let mut display_path = entry.path.to_string();
        if colors_enabled && let Some(color) = get_file_color(&entry.tags) {
            display_path = colorize_string(&display_path, color);
        }
        println!("    - {}", display_path);

        // 3. 每条路径下面紧跟自己的可见标签，避免多路径文件的标签被误合并。
        let mut visible_tags: Vec<String> = entry
            .tags
            .iter()
            .filter(|tag| !tag.starts_with('_'))
            .map(|tag| tag.to_string())
            .collect();
        if colors_enabled && let Some(color) = get_file_color(&entry.tags) {
            visible_tags.push(format!("color:{}", color));
        }
        let display_tags = if visible_tags.is_empty() {
            "(none)".to_string()
        } else {
            visible_tags.join(", ")
        };
        println!("      Tag: {}", display_tags);
    }
    println!("  SHA256 (ID):     {}", path_entry.sha256sum);
    if let Some(file_entry) = &file_entry {
        println!("  Original SHA256: {}", file_entry.original_sha256sum);
    }

    // 系统元数据：保留以 _vavavult_ 开头的
    let system_meta: Vec<_> = file_entry
        .as_ref()
        .map(|entry| {
            entry
                .metadata
                .iter()
                .filter(|m| m.key.starts_with("_vavavult_"))
                .collect()
        })
        .unwrap_or_default();

    // 用户元数据：过滤掉所有以 '_' 开头的键
    let user_meta: Vec<_> = file_entry
        .as_ref()
        .map(|entry| {
            entry
                .metadata
                .iter()
                .filter(|m| !m.key.starts_with('_'))
                .collect()
        })
        .unwrap_or_default();

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
pub fn print_dir_details(directory_entry: &DirectoryEntry) {
    if !directory_entry.path.is_dir() {
        return;
    } // 安全检查
    println!("----------------------------------------");
    println!(
        "  Name:    {}",
        directory_entry.path.dir_name().unwrap_or("/")
    );
    println!("  Type:    Folder");
    println!("  Path:    {}", directory_entry.path);
    println!("  Parent:  {}", directory_entry.parent_path);
    println!(
        "  Items:   {} file(s), {} folder(s)",
        directory_entry.child_file_count, directory_entry.child_directory_count
    );
}

/// 读取某个文件实体的全部路径映射，失败时退回当前列表中的路径。
fn collect_display_path_entries<'a>(
    vault: &Vault,
    fallback_entries: Vec<&'a FilePathEntry>,
) -> Vec<FilePathEntry> {
    let Some(first_entry) = fallback_entries.first() else {
        return Vec::new();
    };

    vault
        .list_paths_by_hash(&first_entry.sha256sum)
        .and_then(|paths| vault.find_by_paths(&paths))
        .unwrap_or_else(|_| fallback_entries.into_iter().cloned().collect())
}

/// 按文件实体哈希归并并打印详细文件信息。
fn print_merged_file_details<'a, I>(vault: &Vault, file_entries: I, colors_enabled: bool)
where
    I: IntoIterator<Item = &'a FilePathEntry>,
{
    let entries: Vec<&FilePathEntry> = file_entries.into_iter().collect();
    let mut printed_hashes = HashSet::new();

    for entry in &entries {
        let hash_key = entry.sha256sum.to_string();
        if !printed_hashes.insert(hash_key) {
            continue;
        }

        // 当前列表中相同文件实体只打印一次，路径详情再扩展为全量路径映射。
        let same_file_entries: Vec<&FilePathEntry> = entries
            .iter()
            .copied()
            .filter(|candidate| candidate.sha256sum == entry.sha256sum)
            .collect();
        let display_path_entries = collect_display_path_entries(vault, same_file_entries);
        let display_path_refs: Vec<&FilePathEntry> = display_path_entries.iter().collect();
        print_file_details_with_paths(vault, entry, &display_path_refs, colors_enabled);
    }
}

/// Takes the result from the list handler and prints it to the console.
pub fn print_list_result(
    vault: &Vault,
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
                        ListPathEntry::Directory(directory_entry) => {
                            print_dir_details(directory_entry)
                        }
                        ListPathEntry::File(_) => {}
                    }
                } else {
                    print_directory_entry(vault, entry, colors_enabled);
                }
            }
            if long {
                print_merged_file_details(
                    vault,
                    entries.iter().filter_map(|entry| match entry {
                        ListPathEntry::Directory(_) => None,
                        ListPathEntry::File(file_path_entry) => Some(file_path_entry),
                    }),
                    colors_enabled,
                );
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

            for file_path_entry in all_files {
                if long {
                    continue;
                } else {
                    print_file_path_item(vault, file_path_entry, colors_enabled);
                }
            }
            if long {
                print_merged_file_details(vault, all_files.iter(), colors_enabled);
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
    println!(
        "  Total Files:    {}({})",
        status.file_count, status.storage_file_count
    );
    println!("  Created At:     {}", create_time_local);
    println!("  Last Updated:   {}", update_time_local);
    println!("--------------------");
}
