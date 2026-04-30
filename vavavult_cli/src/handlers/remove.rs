use crate::core::helpers::{Target, display_path_for_entry, identify_target};
use crate::errors::CliError;
use crate::ui::prompt::confirm_action;
use indicatif::{ProgressBar, ProgressStyle};
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
            DeleteAction::FileByHash(hash) => match vault.remove_file(hash) {
                Ok(_) => success_count += 1,
                Err(e) => {
                    fail_count += 1;
                    eprintln!("Failed to delete {}: {}", target.display, e);
                }
            },
            DeleteAction::FileByPath(path) => match vault.remove_file_by_path(path) {
                Ok(_) => success_count += 1,
                Err(e) => {
                    fail_count += 1;
                    eprintln!("Failed to delete {}: {}", target.display, e);
                }
            },
            DeleteAction::Directory(path) => {
                // 1. 先遍历目录获取所有待删除文件
                let files_in_dir = match vault.list_all_recursive(path) {
                    Ok(files) => files,
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("Failed to list files in directory '{}': {}", path, e);
                        continue;
                    }
                };

                let total_files = files_in_dir.len();

                // 2. 创建进度条，显示文件删除进度
                let pb = if total_files > 0 {
                    let bar = ProgressBar::new(total_files as u64);
                    bar.set_style(
                        ProgressStyle::default_bar()
                            .template(
                                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                            )
                            .unwrap()
                            .progress_chars("#>-"),
                    );
                    Some(bar)
                } else {
                    None
                };

                // 3. 逐一删除文件并更新进度条
                let mut files_deleted = 0;
                let mut dir_delete_failed = false;

                for file_entry in &files_in_dir {
                    match vault.remove_file_by_path(&file_entry.path) {
                        Ok(_) => {
                            files_deleted += 1;
                            if let Some(ref pb) = pb {
                                pb.inc(1);
                            }
                        }
                        Err(e) => {
                            dir_delete_failed = true;
                            if let Some(ref pb) = pb {
                                pb.println(format!(
                                    "Failed to delete file '{}': {}",
                                    file_entry.path, e
                                ));
                            } else {
                                eprintln!("Failed to delete file '{}': {}", file_entry.path, e);
                            }
                        }
                    }
                }

                // 4. 进度条结束，输出汇总信息
                if let Some(ref pb) = pb {
                    pb.finish_with_message(format!(
                        "Deleted {} files from '{}'",
                        files_deleted, path
                    ));
                } else {
                    println!("Directory '{}' is empty, no files to delete.", path);
                }

                if dir_delete_failed {
                    fail_count += 1;
                    eprintln!(
                        "Failed to delete directory '{}': some files could not be deleted",
                        path
                    );
                    continue;
                }

                // 5. 目录已空，最后调用 remove_directory 完成安全校验并删除目录节点
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
