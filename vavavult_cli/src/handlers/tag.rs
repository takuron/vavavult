use std::error::Error;
use std::str::FromStr;
use indicatif::{ProgressBar, ProgressStyle};
use vavavult::common::hash::VaultHash;
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::{QueryResult, Vault};
use crate::utils::{confirm_action, get_all_files_recursively};

/// 辅助函数：根据路径或哈希获取所有受影响的文件。
/// 如果是目录路径，则 *总是* 递归获取所有文件。
/// 返回 (要处理的文件列表, 用于描述目标的字符串)
fn get_files_to_tag(
    vault: &Vault,
    path: Option<String>,
    hash: Option<String>,
) -> Result<(Vec<FileEntry>, String), Box<dyn Error>> {
    if let Some(h) = hash {
        // --- 案例 1: 按哈希 ---
        let hash_obj = VaultHash::from_str(&h)?;
        let file_entry = match vault.find_by_hash(&hash_obj)? {
            QueryResult::Found(entry) => entry,
            QueryResult::NotFound => return Err("File not found by hash.".into()),
        };
        let description = format!("file '{}' (by hash)", file_entry.path);
        Ok((vec![file_entry], description))

    } else if let Some(p) = path {
        // --- 案例 2: 按路径 ---
        let vault_path = VaultPath::from(p.as_str());

        if vault_path.is_file() {
            // 2a: 路径是文件
            let file_entry = match vault.find_by_path(&vault_path)? {
                QueryResult::Found(entry) => entry,
                QueryResult::NotFound => return Err("File not found by path.".into()),
            };
            let description = format!("file '{}'", file_entry.path);
            Ok((vec![file_entry], description))

        } else {
            // 2b: 路径是目录 (自动递归)
            let description = format!("directory '{}' (recursive)", vault_path);
            println!("Recursively scanning directory '{}'...", vault_path);
            // 复用 utils 中的 get_all_files_recursively
            let files = get_all_files_recursively(vault, vault_path.as_str())?;
            Ok((files, description))
        }
    } else {
        unreachable!("Tag command must have either a path or a hash.");
    }
}

/// 主处理器：添加标签
pub fn handle_tag_add(
    vault: &mut Vault,
    path: Option<String>,
    hash: Option<String>,
    tags: &[String],
) -> Result<(), Box<dyn Error>> {
    let (files_to_tag, target_description) = get_files_to_tag(vault, path, hash)?;

    if files_to_tag.is_empty() {
        println!("No files found for {}. Nothing to tag.", target_description);
        return Ok(());
    }

    let tags_as_str: Vec<&str> = tags.iter().map(AsRef::as_ref).collect();
    let tag_list_str = format!("[{}]", tags_as_str.join(", "));

    let prompt = if files_to_tag.len() == 1 {
        format!(
            "Add tags {} to {}?",
            tag_list_str,
            target_description
        )
    } else {
        format!(
            "Add tags {} to {} files from {}?",
            tag_list_str,
            files_to_tag.len(),
            target_description
        )
    };

    if !confirm_action(&prompt)? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // --- 执行 ---
    let total_count = files_to_tag.len();
    let pb = ProgressBar::new(total_count as u64);
    if total_count > 1 {
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [Tagging] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")?
            .progress_chars("#>-"));
    }

    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in &files_to_tag {
        match vault.add_tags(&entry.sha256sum, &tags_as_str) {
            Ok(_) => success_count += 1,
            Err(e) => {
                fail_count += 1;
                pb.println(format!("Failed to tag {}: {}", entry.path, e));
            }
        }
        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Tagging complete.");
    }

    if fail_count > 0 {
        println!("Finished: {} files tagged, {} failed.", success_count, fail_count);
    } else {
        println!("Finished: {} file(s) tagged successfully.", success_count);
    }

    Ok(())
}

/// 主处理器：移除标签
pub fn handle_tag_remove(
    vault: &mut Vault,
    path: Option<String>,
    hash: Option<String>,
    tags: &[String],
) -> Result<(), Box<dyn Error>> {
    let (files_to_tag, target_description) = get_files_to_tag(vault, path, hash)?;

    if files_to_tag.is_empty() {
        println!("No files found for {}. Nothing to modify.", target_description);
        return Ok(());
    }

    let tags_as_str: Vec<&str> = tags.iter().map(AsRef::as_ref).collect();
    let tag_list_str = format!("[{}]", tags_as_str.join(", "));

    let prompt = if files_to_tag.len() == 1 {
        format!(
            "Remove tags {} from {}?",
            tag_list_str,
            target_description
        )
    } else {
        format!(
            "Remove tags {} from {} files from {}?",
            tag_list_str,
            files_to_tag.len(),
            target_description
        )
    };

    if !confirm_action(&prompt)? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // --- 执行 ---
    let total_count = files_to_tag.len();
    let pb = ProgressBar::new(total_count as u64);
    if total_count > 1 {
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [Removing Tags] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")?
            .progress_chars("#>-"));
    }

    let mut success_count = 0;
    let mut files_failed = 0;

    for entry in &files_to_tag {
        let mut all_tags_removed_for_this_file = true;
        for tag in &tags_as_str {
            if let Err(e) = vault.remove_tag(&entry.sha256sum, tag) {
                pb.println(format!("Failed to remove tag '{}' from {}: {}", tag, entry.path, e));
                all_tags_removed_for_this_file = false;
            }
        }
        if all_tags_removed_for_this_file {
            success_count += 1;
        } else {
            files_failed += 1;
        }
        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Tag removal complete.");
    }

    if files_failed > 0 {
        println!("Finished: Tags removed from {} files, {} files had errors.", success_count, files_failed);
    } else {
        println!("Finished: Tags removed from {} file(s) successfully.", success_count);
    }

    Ok(())
}


/// 主处理器：清除所有标签
pub fn handle_tag_clear(
    vault: &mut Vault,
    path: Option<String>,
    hash: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let (files_to_tag, target_description) = get_files_to_tag(vault, path, hash)?;

    if files_to_tag.is_empty() {
        println!("No files found for {}. Nothing to clear.", target_description);
        return Ok(());
    }

    let prompt = if files_to_tag.len() == 1 {
        format!(
            "Are you sure you want to clear ALL tags from {}?",
            target_description
        )
    } else {
        format!(
            "Are you sure you want to clear ALL tags from {} files from {}?",
            files_to_tag.len(),
            target_description
        )
    };

    if !confirm_action(&prompt)? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // --- 执行 ---
    let total_count = files_to_tag.len();
    let pb = ProgressBar::new(total_count as u64);
    if total_count > 1 {
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [Clearing Tags] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")?
            .progress_chars("#>-"));
    }

    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in &files_to_tag {
        match vault.clear_tags(&entry.sha256sum) {
            Ok(_) => success_count += 1,
            Err(e) => {
                fail_count += 1;
                pb.println(format!("Failed to clear tags for {}: {}", entry.path, e));
            }
        }
        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Tag clearing complete.");
    }

    if fail_count > 0 {
        println!("Finished: {} files cleared, {} failed.", success_count, fail_count);
    } else {
        println!("Finished: {} file(s) cleared successfully.", success_count);
    }

    Ok(())
}