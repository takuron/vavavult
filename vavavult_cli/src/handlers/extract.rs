use crate::core::helpers::{
    Target, determine_output_path, find_file_entry, get_all_files_recursively, identify_target,
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
use vavavult::vault::{DirectoryEntry, ExtractionTask, Vault, execute_extraction_task_standalone};

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
            // --- Case 1: Extract by Hash (Single File) ---
            if non_recursive {
                println!("Warning: --non-recursive has no effect when extracting by hash.");
            }
            if parallel {
                println!("Warning: --parallel has no effect when extracting a single file.");
            }

            // 使用 scoped lock 获取 entry
            let file_entry = {
                let vault_guard = vault.lock().unwrap();
                find_file_entry(&vault_guard, &target)?
            };
            handle_extract_single_file(vault, file_entry, &destination, output_name, delete)
        }
        Target::Path(vault_path) => {
            if vault_path.is_file() {
                // --- Case 2: Extract by File Path ---
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
                // --- Case 3: Extract by Directory Path ---
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

/// 处理提取单个文件的逻辑
/// 此函数现在接收一个 `FileEntry`，而不是自己去查找
fn handle_extract_single_file(
    vault: Arc<Mutex<Vault>>,
    file_entry: FileEntry,
    destination: &Path,
    output_name: Option<String>,
    delete: bool,
) -> Result<(), CliError> {
    // 目标路径现在是目录，文件名从 -o 或原始文件名推断
    let final_path = determine_output_path(&file_entry, destination.to_path_buf(), output_name);

    if delete {
        if !confirm_action(&format!(
            "This will extract '{}' to {:?} and then PERMANENTLY DELETE it. Are you sure?",
            file_entry.path, final_path
        ))? {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    println!("Extracting '{}' to {:?}...", file_entry.path, final_path);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // --- 提取 ---
    // (在单文件模式下，并行与否无关紧要，直接提取)
    {
        let vault_guard = vault.lock().unwrap();
        vault_guard.extract_file(&file_entry.sha256sum, &final_path)?;
    } // 锁释放
    println!("File extracted successfully.");

    // --- 删除 ---
    if delete {
        println!("Deleting '{}' from vault...", file_entry.path);
        let mut vault_guard = vault.lock().unwrap();
        vault_guard.remove_file(&file_entry.sha256sum)?;
        println!("File successfully deleted from vault.");
    }
    Ok(())
}

/// 收集文件并分发到单线程或多线程处理器
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

    // --- 1. 收集文件 (加锁) ---
    let files_to_extract = {
        // Scoped lock
        let vault_guard = vault.lock().unwrap();
        if non_recursive {
            println!("(Non-recursive mode enabled)");
            // 使用新的 list_entries 高效 API，直接获取 FileEntry
            let entries = vault_guard.list_by_path(vault_path)?;
            entries
                .into_iter()
                .filter_map(|entry| match entry {
                    DirectoryEntry::File(file_entry) => Some(file_entry),
                    DirectoryEntry::Directory(_) => None, // 在非递归模式下忽略子目录
                })
                .collect()
        } else {
            println!("(Recursive mode enabled)");
            // `get_all_files_recursively` 内部处理 vault_path.as_str()
            get_all_files_recursively(&vault_guard, vault_path.as_str())?
        }
    }; // 锁释放

    if files_to_extract.is_empty() {
        println!("No files found in vault directory '{}'.", vault_path);
        return Ok(());
    }

    // ... (后续逻辑保持不变) ...
    // --- 2. 确认 (不变) ---
    println!(
        "The following {} files will be extracted to {:?}",
        files_to_extract.len(),
        destination
    );
    for entry in &files_to_extract {
        // 计算相对路径
        let relative_path = entry
            .path
            .as_str()
            .strip_prefix(vault_path.as_str())
            .unwrap_or_else(|| entry.path.as_str().trim_start_matches('/'));

        let final_path = destination.join(relative_path);
        let final_path_display = final_path.to_string_lossy().replace('\\', "/");
        println!("  - {} -> \"{}\"", entry.path, final_path_display);
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

    // --- 3. 分发 ---
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

/// (单线程) 执行目录提取
fn run_directory_extract_single_threaded(
    vault: Arc<Mutex<Vault>>,
    files_to_extract: Vec<FileEntry>,
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

    for entry in &files_to_extract {
        // [V2 修改] 计算相对路径
        let relative_path_str = entry
            .path
            .as_str()
            .strip_prefix(base_vault_path.as_str())
            .unwrap_or_else(|| entry.path.as_str().trim_start_matches('/'));

        let final_path = destination.join(relative_path_str);

        if let Some(parent) = final_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                pb.println(format!(
                    "FAILED to create local directory for {}: {}",
                    entry.path, e
                ));
                fail_count += 1;
                pb.inc(1);
                continue;
            }
        }

        // --- 提取 (循环内加锁) ---
        let vault_guard = vault.lock().unwrap();
        match vault_guard.extract_file(&entry.sha256sum, &final_path) {
            Ok(_) => {
                success_count += 1;
                successfully_extracted.push(entry.clone()); // 为删除做准备
            }
            Err(e) => {
                pb.println(format!("FAILED to extract {}: {}", entry.path, e));
                fail_count += 1;
            }
        }
        // 锁释放
        pb.inc(1);
    }

    pb.finish_with_message("Extraction complete.");
    println!("{} succeeded, {} failed.", success_count, fail_count);

    // --- 删除 (循环内加锁) ---
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

        for entry in successfully_extracted {
            let mut vault_guard = vault.lock().unwrap();
            match vault_guard.remove_file(&entry.sha256sum) {
                Ok(_) => pb_delete.println(format!("Deleted {}.", entry.path)),
                Err(e) => pb_delete.println(format!("Failed to delete {}: {}", entry.path, e)),
            }
            pb_delete.inc(1);
        }
        pb_delete.finish_with_message("Deletion complete.");
    }

    Ok(())
}

/// (多线程) 执行目录提取
fn run_directory_extract_parallel(
    vault: Arc<Mutex<Vault>>,
    files_to_extract: Vec<FileEntry>,
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

    // --- 阶段 1: 准备任务 (加锁) ---
    let tasks: Vec<(ExtractionTask, PathBuf, FileEntry)> = {
        let vault_guard = vault.lock().unwrap();
        files_to_extract
            .into_iter()
            .map(|entry| {
                let task = vault_guard.prepare_extraction_task(&entry.sha256sum)?;
                let relative_path_str = entry
                    .path
                    .as_str()
                    .strip_prefix(base_vault_path.as_str())
                    .unwrap_or_else(|| entry.path.as_str().trim_start_matches('/'));
                let final_path = destination.join(relative_path_str);
                Ok((task, final_path, entry))
            })
            .collect::<Result<Vec<_>, CliError>>()?
    };
    // ** 锁在此处释放 **

    // --- 阶段 2: 并行执行 (无锁) ---
    let storage = vault.lock().unwrap().storage.clone();
    let fail_count = Arc::new(AtomicUsize::new(0));

    let extraction_results: Vec<(FileEntry, Result<(), CliError>)> = tasks
        .into_par_iter()
        .map(|(task, final_path, entry)| {
            let pb_clone = pb.clone();
            let fail_count_clone = Arc::clone(&fail_count);

            let execution_result = (|| -> Result<(), CliError> {
                if let Some(parent) = final_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                execute_extraction_task_standalone(storage.as_ref(), &task, &final_path)?;
                Ok(())
            })();

            if let Err(e) = &execution_result {
                pb_clone.println(format!("FAILED to extract {}: {}", entry.path, e));
                fail_count_clone.fetch_add(1, Ordering::SeqCst);
            }

            pb_clone.inc(1);
            (entry, execution_result)
        })
        .collect();

    pb.finish_with_message("Extraction complete.");

    let failures = fail_count.load(Ordering::SeqCst);
    let successes = total_count - failures;
    println!("{} succeeded, {} failed.", successes, failures);

    let successfully_extracted: Vec<FileEntry> = extraction_results
        .into_iter()
        .filter(|(_, result)| result.is_ok())
        .map(|(entry, _)| entry)
        .collect();

    // --- 阶段 3: 串行删除 (循环内加锁) ---
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

        for entry in successfully_extracted {
            let mut vault_guard = vault.lock().unwrap();
            if let Err(e) = vault_guard.remove_file(&entry.sha256sum) {
                pb_delete.println(format!("FAILED to delete {}: {}", entry.path, e));
            }
            pb_delete.inc(1);
        } // 锁释放
        pb_delete.finish_with_message("Deletion complete.");
    }

    Ok(())
}
