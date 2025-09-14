use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::{confirm_action, find_file_entry, get_all_files_recursively};

/// 主处理器，根据参数分发到单文件或批量模式
pub fn handle_tag_add(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
    dir_path: Option<String>,
    tags: &[String],
    recursive: bool
) -> Result<(), Box<dyn Error>> {
    // add_tags 方法需要 `&[&str]` 类型
    let tags_as_str: Vec<&str> = tags.iter().map(AsRef::as_ref).collect();

    if let Some(dir) = dir_path {
        handle_add_tags_directory(vault, &dir, &tags_as_str, recursive)
    } else {
        handle_add_tag_single_file(vault, vault_name, sha256, &tags_as_str)
    }
}

/// 处理为单个文件添加标签
fn handle_add_tag_single_file(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
    tags: &[&str],
) -> Result<(), Box<dyn Error>> {
    let file_entry = find_file_entry(vault, vault_name, sha256)?;

    println!("Adding tags [{}] to '{}'...", tags.join(", "), file_entry.name);
    vault.add_tags(&file_entry.sha256sum, tags)?;

    println!("Tags added successfully.");
    Ok(())
}

/// 处理为整个目录下的文件批量添加标签
fn handle_add_tags_directory(vault: &mut Vault, dir_path: &str, tags: &[&str], recursive: bool) -> Result<(), Box<dyn Error>> {
    println!("Scanning vault directory '{}' to add tags...", dir_path);
    let files_to_tag = if recursive {
        println!("(Recursive mode enabled)");
        get_all_files_recursively(vault, dir_path)?
    } else {
        vault.list_by_path(dir_path)?.files
    };

    if files_to_tag.is_empty() {
        println!("No files found in vault directory '{}'.", dir_path);
        return Ok(());
    }

    println!("The tags [{}] will be added to {} files.", tags.join(", "), files_to_tag.len());
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    let mut success_count = 0;
    for entry in &files_to_tag {
        match vault.add_tags(&entry.sha256sum, tags) {
            Ok(_) => success_count += 1,
            Err(e) => eprintln!("Failed to tag {}: {}", entry.name, e),
        }
    }

    println!("\nBatch tagging complete. {} files tagged successfully.", success_count);
    Ok(())
}

pub fn handle_tag_remove(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
    dir_path: Option<String>,
    tags: &[String],
    recursive: bool
) -> Result<(), Box<dyn Error>> {
    let tags_as_str: Vec<&str> = tags.iter().map(AsRef::as_ref).collect();

    if let Some(dir) = dir_path {
        handle_remove_tags_directory(vault, &dir, &tags_as_str, recursive)
    } else {
        handle_remove_tags_single_file(vault, vault_name, sha256, &tags_as_str)
    }
}

/// 处理为单个文件移除标签
fn handle_remove_tags_single_file(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
    tags: &[&str],
) -> Result<(), Box<dyn Error>> {
    let file_entry = find_file_entry(vault, vault_name, sha256)?;

    println!("Removing tags [{}] from '{}'...", tags.join(", "), file_entry.name);
    for tag in tags {
        vault.remove_tag(&file_entry.sha256sum, tag)?;
    }

    println!("Tags removed successfully.");
    Ok(())
}

/// 处理为整个目录下的文件批量移除标签
fn handle_remove_tags_directory(vault: &mut Vault, dir_path: &str, tags: &[&str], recursive: bool) -> Result<(), Box<dyn Error>> {
    println!("Scanning vault directory '{}' to remove tags...", dir_path);
    let files_to_process = if recursive {
        println!("(Recursive mode enabled)");
        get_all_files_recursively(vault, dir_path)?
    } else {
        vault.list_by_path(dir_path)?.files
    };

    if files_to_process.is_empty() {
        println!("No files found in vault directory '{}'.", dir_path);
        return Ok(());
    }

    println!("The tags [{}] will be removed from {} files.", tags.join(", "), files_to_process.len());
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    let mut success_count = 0;
    for entry in &files_to_process {
        let mut all_tags_removed = true;
        for tag in tags {
            if let Err(e) = vault.remove_tag(&entry.sha256sum, tag) {
                eprintln!("Failed to remove tag '{}' from {}: {}", tag, entry.name, e);
                all_tags_removed = false;
            }
        }
        if all_tags_removed {
            success_count += 1;
        }
    }

    println!("\nBatch removal complete. Tags removed from {} files successfully.", success_count);
    Ok(())
}


pub fn handle_tag_clear(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // 查找目标文件
    let file_entry = find_file_entry(vault, vault_name, sha256)?;

    // 在执行破坏性操作前，向用户请求确认
    if !confirm_action(&format!(
        "Are you sure you want to clear ALL tags from '{}'?",
        file_entry.name
    ))? {
        println!("Operation cancelled.");
        return Ok(());
    }

    println!("Clearing all tags from '{}'...", file_entry.name);

    // 调用核心库的 clear_tags 方法
    vault.clear_tags(&file_entry.sha256sum)?;

    println!("All tags have been cleared successfully.");
    Ok(())
}