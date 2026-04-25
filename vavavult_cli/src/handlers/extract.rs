use crate::core::helpers::{
    Target, determine_output_path, find_file_entry, first_path_for_entry, identify_target,
};
use crate::errors::CliError;
use crate::ui::prompt::confirm_action;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use vavavult::file::{FileEntry, VaultPath};
use vavavult::vault::{ExtractionTask, ListPathEntry, QueryFileResult, Vault};

#[derive(Clone)]
struct ExtractionCandidate {
    entry: FileEntry,
    path: VaultPath,
}

/// 主处理函数，根据新的 CLI 签名分发任务
pub fn handle_extract(
    vault: Arc<Mutex<Vault>>,
    target: String,
    destination: PathBuf,
    output_name: Option<String>,
    non_recursive: bool,
    delete: bool,
    parallel: bool,
) -> Result<(), CliError> {
    let target_obj = identify_target(&target)?;

    match target_obj {
        Target::Hash(_) => {
            if non_recursive {
                println!("Warning: --non-recursive has no effect when extracting by hash.");
            }
            if parallel {
                println!("Warning: --parallel has no effect when extracting a single file.");
            }

            let file_entry = {
                let vault_guard = vault.lock().unwrap();
                find_file_entry(&vault_guard, &target)?
            };
            handle_extract_single_file(vault, file_entry, &destination, output_name, delete)
        }
        Target::Path(vault_path) => {
            if vault_path.is_file() {
                if non_recursive {
                    println!(
                        "Warning: --non-recursive has no effect when extracting a single file."
                    );
                }
                if parallel {
                    println!("Warning: --parallel has no effect when extracting a single file.");
                }
                let file_entry = {
                    let vault_guard = vault.lock().unwrap();
                    find_file_entry(&vault_guard, &target)?
                };
                handle_extract_single_file(vault, file_entry, &destination, output_name, delete)
            } else {
                if output_name.is_some() {
                    return Err(CliError::InvalidCommand(
                        "--output (-o) cannot be used when extracting a directory.".to_string(),
                    ));
                }
                handle_extract_directory(
                    vault,
                    &vault_path,
                    &destination,
                    non_recursive,
                    delete,
                    parallel,
                )
            }
        }
    }
}

fn handle_extract_single_file(
    vault: Arc<Mutex<Vault>>,
    file_entry: FileEntry,
    destination: &Path,
    output_name: Option<String>,
    delete: bool,
) -> Result<(), CliError> {
    let (final_path, display_path, source_path) = {
        let vault_guard = vault.lock().unwrap();
        let source_path = first_path_for_entry(&vault_guard, &file_entry)?;
        (
            determine_output_path(
                &vault_guard,
                &file_entry,
                destination.to_path_buf(),
                output_name,
            ),
            source_path.to_string(),
            source_path,
        )
    };

    if delete
        && !confirm_action(&format!(
            "This will extract '{}' to {:?} and then PERMANENTLY DELETE it. Are you sure?",
            display_path, final_path
        ))?
    {
        println!("Operation cancelled.");
        return Ok(());
    }

    println!("Extracting '{}' to {:?}...", display_path, final_path);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }

    {
        let vault_guard = vault.lock().unwrap();
        vault_guard.extract_file(&file_entry.sha256sum, &final_path)?;
    }
    println!("File extracted successfully.");

    if delete {
        println!("Deleting '{}' from vault...", display_path);
        let mut vault_guard = vault.lock().unwrap();
        vault_guard.remove_file_by_path(&source_path)?;
        println!("File successfully deleted from vault.");
    }
    Ok(())
}

fn handle_extract_directory(
    vault: Arc<Mutex<Vault>>,
    vault_path: &VaultPath,
    destination: &Path,
    non_recursive: bool,
    delete: bool,
    parallel: bool,
) -> Result<(), CliError> {
    println!(
        "Scanning vault directory '{}' for extraction...",
        vault_path
    );

    let files_to_extract = {
        let vault_guard = vault.lock().unwrap();
        if non_recursive {
            println!("(Non-recursive mode enabled)");
            vault_guard
                .list_by_path(vault_path)?
                .into_iter()
                .filter_map(|entry| match entry {
                    ListPathEntry::File(file_path_entry) => {
                        match vault_guard.find_by_hash(&file_path_entry.sha256sum) {
                            Ok(QueryFileResult::Found(file_entry)) => Some(ExtractionCandidate {
                                entry: file_entry,
                                path: file_path_entry.path,
                            }),
                            _ => None,
                        }
                    }
                    ListPathEntry::Directory(_) => None,
                })
                .collect::<Vec<_>>()
        } else {
            println!("(Recursive mode enabled)");
            vault_guard
                .list_all_recursive(vault_path)?
                .into_iter()
                .filter_map(|file_path_entry| {
                    match vault_guard.find_by_hash(&file_path_entry.sha256sum) {
                        Ok(QueryFileResult::Found(file_entry)) => Some(Ok(ExtractionCandidate {
                            entry: file_entry,
                            path: file_path_entry.path,
                        })),
                        Ok(QueryFileResult::NotFound) => None,
                        Err(err) => Some(Err(CliError::from(err))),
                    }
                })
                .collect::<Result<Vec<_>, CliError>>()?
        }
    };

    if files_to_extract.is_empty() {
        println!("No files found in vault directory '{}'.", vault_path);
        return Ok(());
    }

    println!(
        "The following {} files will be extracted to {:?}",
        files_to_extract.len(),
        destination
    );
    for candidate in &files_to_extract {
        let relative_path = relative_vault_path(&candidate.path, vault_path);
        let final_path = destination.join(relative_path);
        let final_path_display = final_path.to_string_lossy().replace('\\', "/");
        println!("  - {} -> \"{}\"", candidate.path, final_path_display);
    }

    if delete {
        println!(
            "WARNING: The original files will be PERMANENTLY DELETED from the vault after extraction."
        );
    }
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    if parallel {
        run_directory_extract_parallel(vault, files_to_extract, vault_path, destination, delete)
    } else {
        run_directory_extract_single_threaded(
            vault,
            files_to_extract,
            vault_path,
            destination,
            delete,
        )
    }
}

fn relative_vault_path<'a>(path: &'a VaultPath, base_path: &VaultPath) -> &'a str {
    path.as_str()
        .strip_prefix(base_path.as_str())
        .unwrap_or_else(|| path.as_str().trim_start_matches('/'))
}

fn run_directory_extract_single_threaded(
    vault: Arc<Mutex<Vault>>,
    files_to_extract: Vec<ExtractionCandidate>,
    base_vault_path: &VaultPath,
    destination: &Path,
    delete: bool,
) -> Result<(), CliError> {
    let pb = ProgressBar::new(files_to_extract.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .map_err(|e| CliError::Unexpected(e.to_string()))?
            .progress_chars("#>-"),
    );

    let mut success_count = 0;
    let mut fail_count = 0;
    let mut successfully_extracted = Vec::new();

    for candidate in &files_to_extract {
        let relative_path_str = relative_vault_path(&candidate.path, base_vault_path);
        let final_path = destination.join(relative_path_str);

        if let Some(parent) = final_path.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            pb.println(format!(
                "FAILED to create local directory for {}: {}",
                candidate.path, e
            ));
            fail_count += 1;
            pb.inc(1);
            continue;
        }

        let vault_guard = vault.lock().unwrap();
        match vault_guard.extract_file(&candidate.entry.sha256sum, &final_path) {
            Ok(_) => {
                success_count += 1;
                successfully_extracted.push(candidate.clone());
            }
            Err(e) => {
                fail_count += 1;
                pb.println(format!("FAILED to extract {}: {}", candidate.path, e));
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("Extraction complete.");
    println!("{} succeeded, {} failed.", success_count, fail_count);

    if delete && success_count > 0 {
        if !confirm_action("Confirm deletion of successfully extracted files?")? {
            println!("Deletion cancelled.");
            return Ok(());
        }

        let pb_delete = ProgressBar::new(success_count as u64);
        pb_delete.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [Deleting] [{elapsed_precise}] [{bar:40.red/yellow}] {pos}/{len}",
                )
                .map_err(|e| CliError::Unexpected(e.to_string()))?
                .progress_chars("#>-"),
        );

        for candidate in successfully_extracted {
            let mut vault_guard = vault.lock().unwrap();
            let display_path = candidate.path.to_string();
            match vault_guard.remove_file_by_path(&candidate.path) {
                Ok(_) => pb_delete.println(format!("Deleted {}.", display_path)),
                Err(e) => pb_delete.println(format!("Failed to delete {}: {}", display_path, e)),
            }
            pb_delete.inc(1);
        }
        pb_delete.finish_with_message("Deletion complete.");
    }

    Ok(())
}

fn run_directory_extract_parallel(
    vault: Arc<Mutex<Vault>>,
    files_to_extract: Vec<ExtractionCandidate>,
    base_vault_path: &VaultPath,
    destination: &Path,
    delete: bool,
) -> Result<(), CliError> {
    let total_count = files_to_extract.len();
    let pb = ProgressBar::new(total_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [Extracting] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .map_err(|e| CliError::Unexpected(e.to_string()))?
            .progress_chars("#>-"),
    );

    let tasks: Vec<(ExtractionTask, PathBuf, ExtractionCandidate)> = {
        let vault_guard = vault.lock().unwrap();
        files_to_extract
            .into_iter()
            .map(|candidate| {
                let task = vault_guard.prepare_extraction_task(&candidate.entry.sha256sum)?;
                let relative_path_str = relative_vault_path(&candidate.path, base_vault_path);
                let final_path = destination.join(relative_path_str);
                Ok((task, final_path, candidate))
            })
            .collect::<Result<Vec<_>, CliError>>()?
    };

    let storage = vault.lock().unwrap().storage.clone();
    let fail_count = Arc::new(AtomicUsize::new(0));

    let extraction_results: Vec<(ExtractionCandidate, Result<(), CliError>)> = tasks
        .into_par_iter()
        .map(|(task, final_path, candidate)| {
            let pb_clone = pb.clone();
            let fail_count_clone = Arc::clone(&fail_count);
            let display_path = candidate.path.to_string();

            let execution_result = (|| -> Result<(), CliError> {
                if let Some(parent) = final_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                Vault::decrypt_extraction_task_to_file(storage.as_ref(), &task, &final_path)?;
                Ok(())
            })();

            if let Err(e) = &execution_result {
                pb_clone.println(format!("FAILED to extract {}: {}", display_path, e));
                fail_count_clone.fetch_add(1, Ordering::SeqCst);
            }

            pb_clone.inc(1);
            (candidate, execution_result)
        })
        .collect();

    pb.finish_with_message("Extraction complete.");

    let failures = fail_count.load(Ordering::SeqCst);
    let successes = total_count - failures;
    println!("{} succeeded, {} failed.", successes, failures);

    let successfully_extracted: Vec<ExtractionCandidate> = extraction_results
        .into_iter()
        .filter(|(_, result)| result.is_ok())
        .map(|(candidate, _)| candidate)
        .collect();

    if delete && successes > 0 {
        if !confirm_action("Confirm deletion of successfully extracted files?")? {
            println!("Deletion cancelled.");
            return Ok(());
        }

        let pb_delete = ProgressBar::new(successes as u64);
        pb_delete.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [Deleting] [{elapsed_precise}] [{bar:40.red/yellow}] {pos}/{len}",
                )
                .map_err(|e| CliError::Unexpected(e.to_string()))?
                .progress_chars("#>-"),
        );

        for candidate in successfully_extracted {
            let mut vault_guard = vault.lock().unwrap();
            let display_path = candidate.path.to_string();
            if let Err(e) = vault_guard.remove_file_by_path(&candidate.path) {
                pb_delete.println(format!("FAILED to delete {}: {}", display_path, e));
            }
            pb_delete.inc(1);
        }
        pb_delete.finish_with_message("Deletion complete.");
    }

    Ok(())
}

