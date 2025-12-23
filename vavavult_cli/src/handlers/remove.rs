use crate::errors::CliError;
use crate::utils::{Target, confirm_action, get_all_files_recursively, identify_target};
use indicatif::{ProgressBar, ProgressStyle};
use vavavult::vault::{QueryResult, Vault};

/// 处理 'rm' (Remove) 命令
pub fn handle_remove(
    vault: &mut Vault,
    target: &str,
    recursive: bool,
    force: bool,
) -> Result<(), CliError> {
    let target_obj = identify_target(target)?;

    let (files_to_delete, target_description) = match target_obj {
        Target::Hash(hash) => {
            // --- 案例 1: 按哈希删除 ---
            if recursive {
                println!("Warning: -r (recursive) has no effect when deleting by hash.");
            }
            // find_by_hash
            let file_entry = match vault.find_by_hash(&hash)? {
                QueryResult::Found(entry) => entry,
                QueryResult::NotFound => {
                    return Err(CliError::EntryNotFound(
                        "File not found by hash.".to_string(),
                    ));
                }
            };
            let description = format!("file '{}' (by hash)", file_entry.path);
            (vec![file_entry], description)
        }
        Target::Path(vault_path) => {
            // --- 案例 2: 按路径删除 ---
            if vault_path.is_file() {
                // 2a: 路径是文件
                let file_entry = match vault.find_by_path(&vault_path)? {
                    QueryResult::Found(entry) => entry,
                    QueryResult::NotFound => {
                        return Err(CliError::EntryNotFound(
                            "File not found by path.".to_string(),
                        ));
                    }
                };
                let description = format!("file '{}'", file_entry.path);
                (vec![file_entry], description)
            } else {
                // 2b: 路径是目录
                let description = format!("directory '{}'", vault_path);
                if !recursive {
                    return Err(CliError::InvalidTarget(format!(
                        "Cannot remove '{}': It is a directory. Use -r (recursive) to delete.",
                        vault_path
                    )));
                }
                println!("Recursively scanning directory '{}'...", vault_path);
                let files = get_all_files_recursively(vault, vault_path.as_str())?;
                (files, description)
            }
        }
    };

    // --- 确认阶段 ---
    if files_to_delete.is_empty() {
        println!(
            "No files found matching {}. Nothing to delete.",
            target_description
        );
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
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [Deleting] [{elapsed_precise}] [{bar:40.red/yellow}] {pos}/{len}",
                )
                .map_err(|e| CliError::Unexpected(e.to_string()))?
                .progress_chars("#>-"),
        );
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
        eprintln!(
            "Deletion finished: {} succeeded, {} failed.",
            success_count, fail_count
        );
    } else {
        println!(
            "Deletion finished: {} file(s) successfully deleted.",
            success_count
        );
    }

    Ok(())
}
