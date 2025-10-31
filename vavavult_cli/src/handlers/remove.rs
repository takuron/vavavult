use std::error::Error;
use std::str::FromStr;
use indicatif::{ProgressBar, ProgressStyle};
use vavavult::common::hash::VaultHash;
use vavavult::file::{VaultPath};
use vavavult::vault::{QueryResult, Vault};
use crate::utils::{confirm_action, get_all_files_recursively};

/// 处理 'rm' (Remove) 命令
pub fn handle_remove(
    vault: &mut Vault,
    path: Option<String>,
    hash: Option<String>,
    recursive: bool,
    force: bool,
) -> Result<(), Box<dyn Error>> {

    let (files_to_delete, target_description) = if let Some(h) = hash {
        // --- 案例 1: 按哈希删除 ---
        if recursive {
            println!("Warning: -r (recursive) has no effect when deleting by hash.");
        }

        let hash_obj = VaultHash::from_str(&h)?;
        let file_entry = match vault.find_by_hash(&hash_obj)? {
            QueryResult::Found(entry) => entry,
            QueryResult::NotFound => return Err("File not found by hash.".into()),
        };
        let description = format!("file '{}' (by hash)", file_entry.path);
        (vec![file_entry], description) // 返回元组

    } else if let Some(p) = path {
        // --- 案例 2: 按路径删除 ---
        let vault_path = VaultPath::from(p.as_str());

        if vault_path.is_file() {
            // 2a: 路径是文件
            let file_entry = match vault.find_by_path(&vault_path)? {
                QueryResult::Found(entry) => entry,
                QueryResult::NotFound => return Err("File not found by path.".into()),
            };
            let description = format!("file '{}'", file_entry.path);
            (vec![file_entry], description) // 返回元组

        } else {
            // 2b: 路径是目录
            let description = format!("directory '{}'", vault_path);
            if !recursive {
                return Err(format!("Cannot remove '{}': It is a directory. Use -r (recursive) to delete.", vault_path).into());
            }

            // 递归获取所有文件
            println!("Recursively scanning directory '{}'...", vault_path);
            let files = get_all_files_recursively(vault, vault_path.as_str())?;
            (files, description) // 返回元组
        }
    } else {
        // Clap 应该阻止这种情况发生
        unreachable!("Delete command must have either a path or a hash.");
    };

    // --- 确认阶段 ---
    if files_to_delete.is_empty() {
        println!("No files found matching {}. Nothing to delete.", target_description);
        return Ok(());
    }

    if !force {
        let prompt = if files_to_delete.len() == 1 {
            format!(
                "Are you sure you want to PERMANENTLY DELETE {}?",
                target_description
            )
        } else {
            format!(
                "Are you sure you want to PERMANENTLY DELETE {} files from {}?",
                files_to_delete.len(),
                target_description
            )
        };

        if !confirm_action(&prompt)? {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    // --- 删除阶段 ---
    let total_count = files_to_delete.len();
    let pb = ProgressBar::new(total_count as u64);
    if total_count > 1 {
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [Deleting] [{elapsed_precise}] [{bar:40.red/yellow}] {pos}/{len}")?
            .progress_chars("#>-"));
    }

    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in files_to_delete {
        match vault.remove_file(&entry.sha256sum) {
            Ok(_) => {
                success_count += 1;
            }
            Err(e) => {
                fail_count += 1;
                pb.println(format!("Failed to delete {}: {}", entry.path, e));
            }
        }
        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Deletion complete.");
    }

    if fail_count > 0 {
        eprintln!("Deletion finished: {} succeeded, {} failed.", success_count, fail_count);
    } else {
        println!("Deletion finished: {} file(s) successfully deleted.", success_count);
    }

    Ok(())
}