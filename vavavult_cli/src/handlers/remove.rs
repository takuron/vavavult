use crate::core::helpers::{Target, display_path_for_entry, identify_target};
use crate::errors::CliError;
use crate::ui::prompt::confirm_action;
use vavavult::common::hash::VaultHash;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryFileResult, QueryPathResult, Vault};

struct DeleteTarget {
    action: DeleteAction,
    display: String,
}

enum DeleteAction {
    FileByHash(VaultHash),
    FileByPath(VaultPath),
    Directory(VaultPath),
}

/// 处理 'rm' (Remove) 命令
pub fn handle_remove(
    vault: &mut Vault,
    target: &str,
    recursive: bool,
    yes: bool,
) -> Result<(), CliError> {
    let target_obj = identify_target(target)?;

    let (targets_to_delete, target_description) = match target_obj {
        Target::Hash(hash) => {
            if recursive {
                println!("Warning: -r (recursive) has no effect when deleting by hash.");
            }

            let file_entry = match vault.find_by_hash(&hash)? {
                QueryFileResult::Found(entry) => entry,
                QueryFileResult::NotFound => {
                    return Err(CliError::EntryNotFound(
                        "File not found by hash.".to_string(),
                    ));
                }
            };
            let display = display_path_for_entry(vault, &file_entry);
            (
                vec![DeleteTarget {
                    action: DeleteAction::FileByHash(file_entry.sha256sum),
                    display: display.clone(),
                }],
                format!("file '{}' (by hash)", display),
            )
        }
        Target::Path(vault_path) => {
            if vault_path.is_file() {
                match vault.find_by_path(&vault_path)? {
                    QueryPathResult::Found(_) => {}
                    QueryPathResult::NotFound => {
                        return Err(CliError::EntryNotFound(
                            "File not found by path.".to_string(),
                        ));
                    }
                }
                let description = format!("file '{}'", vault_path);
                (
                    vec![DeleteTarget {
                        action: DeleteAction::FileByPath(vault_path.clone()),
                        display: vault_path.to_string(),
                    }],
                    description,
                )
            } else {
                let description = format!("directory '{}'", vault_path);
                if !recursive {
                    return Err(CliError::InvalidTarget(format!(
                        "Cannot remove '{}': It is a directory. Use -r (recursive) to delete.",
                        vault_path
                    )));
                }
                (
                    vec![DeleteTarget {
                        action: DeleteAction::Directory(vault_path.clone()),
                        display: vault_path.to_string(),
                    }],
                    description,
                )
            }
        }
    };

    if targets_to_delete.is_empty() {
        println!(
            "No files found matching {}. Nothing to delete.",
            target_description
        );
        return Ok(());
    }

    if !yes {
        let prompt = if targets_to_delete.len() == 1 {
            format!(
                "Are you sure you want to PERMANENTLY DELETE {}?",
                target_description
            )
        } else {
            format!(
                "Are you sure you want to PERMANENTLY DELETE {} targets from {}?",
                targets_to_delete.len(),
                target_description
            )
        };

        if !confirm_action(&prompt)? {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    let mut success_count = 0;
    let mut fail_count = 0;

    for target in targets_to_delete {
        match &target.action {
            DeleteAction::FileByHash(hash) => {
                match vault.remove_file(hash) {
                    Ok(_) => success_count += 1,
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("Failed to delete {}: {}", target.display, e);
                    }
                }
            }
            DeleteAction::FileByPath(path) => {
                match vault.remove_file_by_path(path) {
                    Ok(_) => success_count += 1,
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("Failed to delete {}: {}", target.display, e);
                    }
                }
            }
            DeleteAction::Directory(path) => {
                // 1. 先遍历目录获取所有文件
                let files_in_dir = match vault.list_all_recursive(path) {
                    Ok(files) => files,
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("Failed to list files in directory '{}': {}", path, e);
                        continue;
                    }
                };

                // 2. 逐一删除文件
                let mut files_deleted = 0;
                let mut dir_delete_failed = false;

                for file_entry in &files_in_dir {
                    match vault.remove_file_by_path(&file_entry.path) {
                        Ok(_) => {
                            files_deleted += 1;
                        }
                        Err(e) => {
                            dir_delete_failed = true;
                            eprintln!("Failed to delete file '{}': {}", file_entry.path, e);
                        }
                    }
                }

                if files_deleted > 0 {
                    println!("Deleted {} files from directory '{}'", files_deleted, path);
                }

                if dir_delete_failed {
                    fail_count += 1;
                    eprintln!("Failed to delete directory '{}': some files could not be deleted", path);
                    continue;
                }

                // 3. 最后删除目录本身
                match vault.remove_directory(path) {
                    Ok(_) => success_count += 1,
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("Failed to delete directory '{}': {}", path, e);
                    }
                }
            }
        }
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
