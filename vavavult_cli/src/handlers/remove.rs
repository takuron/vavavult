use crate::core::helpers::{Target, display_path_for_entry, identify_target};
use crate::errors::CliError;
use crate::ui::prompt::confirm_action;
use indicatif::{ProgressBar, ProgressStyle};
use vavavult::common::hash::VaultHash;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryFileResult, QueryPathResult, Vault};

struct DeleteTarget {
    hash: Option<VaultHash>,
    path: Option<VaultPath>,
    display: String,
}

/// 处理 'rm' (Remove) 命令
pub fn handle_remove(
    vault: &mut Vault,
    target: &str,
    recursive: bool,
    force: bool,
    yes: bool,
) -> Result<(), CliError> {
    let target_obj = identify_target(target)?;

    let (files_to_delete, target_description) = match target_obj {
        Target::Hash(hash) => {
            if recursive {
                println!("Warning: -r (recursive) has no effect when deleting by hash.");
            }

            if force {
                let display = hash.to_string();
                (
                    vec![DeleteTarget {
                        hash: Some(hash),
                        path: None,
                        display: display.clone(),
                    }],
                    format!("file '{}' (by hash)", display),
                )
            } else {
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
                        hash: Some(file_entry.sha256sum),
                        path: None,
                        display: display.clone(),
                    }],
                    format!("file '{}' (by hash)", display),
                )
            }
        }
        Target::Path(vault_path) => {
            if vault_path.is_file() {
                if force {
                    let description = format!("file '{}'", vault_path);
                    (
                        vec![DeleteTarget {
                            hash: None,
                            path: Some(vault_path.clone()),
                            display: vault_path.to_string(),
                        }],
                        description,
                    )
                } else {
                    let file_entry = match vault.find_by_path(&vault_path)? {
                        QueryPathResult::Found(entry) => entry,
                        QueryPathResult::NotFound => {
                            return Err(CliError::EntryNotFound(
                                "File not found by path.".to_string(),
                            ));
                        }
                    };
                    let description = format!("file '{}'", vault_path);
                    (
                        vec![DeleteTarget {
                            hash: Some(file_entry.sha256sum),
                            path: Some(vault_path.clone()),
                            display: vault_path.to_string(),
                        }],
                        description,
                    )
                }
            } else {
                let description = format!("directory '{}'", vault_path);
                if !recursive {
                    return Err(CliError::InvalidTarget(format!(
                        "Cannot remove '{}': It is a directory. Use -r (recursive) to delete.",
                        vault_path
                    )));
                }
                println!("Recursively scanning directory '{}'...", vault_path);
                let files = vault.list_all_recursive(&vault_path)?;
                let delete_targets = files
                    .into_iter()
                    .map(|file_path_entry| {
                        Ok(DeleteTarget {
                            hash: Some(file_path_entry.sha256sum),
                            display: file_path_entry.path.to_string(),
                            path: Some(file_path_entry.path),
                        })
                    })
                    .collect::<Result<Vec<_>, CliError>>()?;
                (delete_targets, description)
            }
        }
    };

    if files_to_delete.is_empty() {
        println!(
            "No files found matching {}. Nothing to delete.",
            target_description
        );
        return Ok(());
    }

    if !yes {
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

    for target in files_to_delete {
        let result = if let Some(path) = &target.path {
            vault.remove_file_by_path(path).map_err(|e| e.to_string())
        } else if let Some(hash) = &target.hash {
            if force {
                vault.force_remove_file(hash).map_err(|e| e.to_string())
            } else {
                vault.remove_file(hash).map_err(|e| e.to_string())
            }
        } else {
            Err("Internal delete target has neither path nor hash.".to_string())
        };

        match result {
            Ok(_) => success_count += 1,
            Err(e) => {
                fail_count += 1;
                pb.println(format!("Failed to delete {}: {}", target.display, e));
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

