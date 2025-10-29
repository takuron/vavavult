use std::error::Error;
use std::{fs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use indicatif::{ProgressBar, ProgressStyle};
use vavavult::vault::{FileEntry, Vault};
use rayon::prelude::*;
use crate::utils::{confirm_action, determine_output_path, find_file_entry, get_all_files_recursively};

// 更新主处理函数签名
pub fn handle_extract(vault: Arc<Mutex<Vault>>, vault_name:Option<String>, sha256:Option<String>, dir_path:Option<String>, destination:PathBuf, output_name:Option<String>, delete:bool, recursive: bool, parallel: bool) -> Result<(), Box<dyn Error>> {
    if let Some(dir) = dir_path {
        if parallel {
            handle_extract_directory_parallel(vault, &dir, &destination, delete, recursive)
        } else {
            handle_extract_directory_single_threaded(vault, &dir, &destination, delete, recursive)
        }
    } else {
        handle_extract_single_file(vault, vault_name, sha256, &destination, output_name, delete)
    }
}

/// 处理提取单个文件的逻辑
fn handle_extract_single_file(vault: Arc<Mutex<Vault>>, vault_name: Option<String>, sha256: Option<String>, destination: &Path, output_name: Option<String>, delete: bool) -> Result<(), Box<dyn Error>> {
    let mut vault_guard = vault.lock().unwrap();
    let file_entry = find_file_entry(&vault_guard, vault_name, sha256)?;
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
    vault_guard.extract_file(&file_entry.sha256sum, &final_path)?;
    println!("File extracted successfully.");

    if delete {
        println!("Deleting '{}' from vault...", file_entry.path);
        vault_guard.remove_file(&file_entry.sha256sum)?;
        println!("File successfully deleted from vault.");
    }
    Ok(())
}

/// (单线程) 处理提取整个目录的逻辑
fn handle_extract_directory_single_threaded(vault: Arc<Mutex<Vault>>, dir_path: &str, destination: &Path, delete: bool, recursive: bool) -> Result<(), Box<dyn Error>> {
    println!("Scanning vault directory '{}' for extraction...", dir_path);

    // 文件收集逻辑与之前相同
    let files_to_extract = {
        let vault_guard = vault.lock().unwrap();
        if recursive {
            println!("(Recursive mode enabled)");
            get_all_files_recursively(&vault_guard, dir_path)?
        } else {
            vault_guard.list_by_path(dir_path)?.files
        }
    };

    if files_to_extract.is_empty() {
        println!("No files found in vault directory '{}'.", dir_path);
        return Ok(());
    }

    println!("The following {} files will be extracted to {:?}", files_to_extract.len(), destination);

    // --- 修改: 在打印前统一路径分隔符 ---
    for entry in &files_to_extract {
        let relative_path = Path::new(&entry.path).strip_prefix(dir_path).unwrap_or(Path::new(&entry.path));
        let final_path = destination.join(relative_path);
        let final_path_display = final_path.to_string_lossy().replace('\\', "/");
        println!("  - {} -> \"{}\"", entry.path, final_path_display);
    }

    if delete {
        println!("WARNING: The original files will be PERMANENTLY DELETED from the vault after extraction.");
    }
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 带进度条的单线程执行
    let pb = ProgressBar::new(files_to_extract.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
        .progress_chars("#>-"));

    let mut success_count = 0;
    let mut fail_count = 0;
    for entry in &files_to_extract {
        let relative_path = Path::new(&entry.path).strip_prefix(dir_path).unwrap_or(Path::new(&entry.path));
        let final_path = destination.join(relative_path);

        if let Some(parent) = final_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                pb.println(format!("FAILED to create local directory for {}: {}", entry.path, e));
                fail_count += 1;
                pb.inc(1);
                continue;
            }
        }

        let vault_guard = vault.lock().unwrap();
        match vault_guard.extract_file(&entry.sha256sum, &final_path) {
            Ok(_) => {
                success_count += 1;
            }
            Err(e) => {
                pb.println(format!("FAILED to extract {}: {}", entry.path, e));
                fail_count += 1;
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("Extraction complete.");
    println!("{} succeeded, {} failed.", success_count, fail_count);

    if delete && success_count > 0 {
        println!("\nDeleting {} extracted files from vault...", success_count);
        if !confirm_action("Confirm deletion of successfully extracted files?")? {
            println!("Deletion cancelled.");
            return Ok(());
        }
        for entry in files_to_extract.iter().filter(|_| fail_count == 0) { // Simple filter for now
            let mut vault_guard = vault.lock().unwrap();
            match vault_guard.remove_file(&entry.sha256sum) {
                Ok(_) => println!("Deleted {}.", entry.path),
                Err(e) => eprintln!("Failed to delete {}: {}", entry.path, e),
            }
        }
    }

    Ok(())
}

/// (多线程) 处理提取整个目录的逻辑
fn handle_extract_directory_parallel(vault: Arc<Mutex<Vault>>, dir_path: &str, destination: &Path, delete: bool, recursive: bool) -> Result<(), Box<dyn Error>> {
    println!("Scanning vault directory '{}' for extraction (parallel mode)...", dir_path);

    let files_to_extract = {
        let vault_guard = vault.lock().unwrap();
        if recursive {
            println!("(Recursive mode enabled)");
            get_all_files_recursively(&vault_guard, dir_path)?
        } else {
            vault_guard.list_by_path(dir_path)?.files
        }
    };

    if files_to_extract.is_empty() {
        println!("No files found in vault directory '{}'.", dir_path);
        return Ok(());
    }

    println!("The following {} files will be extracted to {:?}", files_to_extract.len(), destination);

    // --- 修改: 在打印前统一路径分隔符 ---
    for entry in &files_to_extract {
        let relative_path = Path::new(&entry.path).strip_prefix(dir_path).unwrap_or(Path::new(&entry.path));
        let final_path = destination.join(relative_path);
        let final_path_display = final_path.to_string_lossy().replace('\\', "/");
        println!("  - {} -> \"{}\"", entry.path, final_path_display);
    }

    if delete {
        println!("WARNING: The original files will be PERMANENTLY DELETED from the vault after extraction.");
    }
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // --- 1. 并行提取 ---
    let pb = ProgressBar::new(files_to_extract.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [Extracting] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
        .progress_chars("#>-"));

    let extraction_results: Vec<(FileEntry, Result<(), _>)> = files_to_extract
        .into_par_iter()
        .map(|entry| {
            let vault_clone = Arc::clone(&vault);
            let pb_clone = pb.clone();

            let relative_path = Path::new(&entry.path).strip_prefix(dir_path).unwrap_or(Path::new(&entry.path));
            let final_path = destination.join(relative_path);

            if let Some(parent) = final_path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    pb_clone.println(format!("FAILED to create local directory for {}: {}", entry.path, e));
                    pb_clone.inc(1);
                    return (entry, Err(Box::new(e) as Box<dyn Error + Send + Sync>));
                }
            }

            let result = {
                let vault_guard = vault_clone.lock().unwrap();
                vault_guard.extract_file(&entry.sha256sum, &final_path)
            };

            if let Err(e) = &result {
                pb_clone.println(format!("FAILED to extract {}: {}", entry.path, e));
            }

            pb_clone.inc(1);
            (entry, result.map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>))
        })
        .collect();

    pb.finish_with_message("Extraction complete.");

    let successfully_extracted: Vec<FileEntry> = extraction_results
        .iter()
        .filter(|(_, result)| result.is_ok())
        .map(|(entry, _)| entry.clone())
        .collect();

    let success_count = successfully_extracted.len();
    let fail_count = extraction_results.len() - success_count;
    println!("{} succeeded, {} failed.", success_count, fail_count);


    // --- 2. 串行删除 (如果需要) ---
    if delete && success_count > 0 {
        println!("\nDeleting {} successfully extracted files from the vault...", success_count);
        if !confirm_action("Confirm deletion?")? {
            println!("Deletion cancelled.");
            return Ok(());
        }

        let pb_delete = ProgressBar::new(success_count as u64);
        pb_delete.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [Deleting] [{elapsed_precise}] [{bar:40.red/yellow}] {pos}/{len}")?
            .progress_chars("#>-"));

        for entry in successfully_extracted {
            let mut vault_guard = vault.lock().unwrap();
            if let Err(e) = vault_guard.remove_file(&entry.sha256sum) {
                pb_delete.println(format!("FAILED to delete {}: {}", entry.path, e));
            }
            pb_delete.inc(1);
        }
        pb_delete.finish_with_message("Deletion complete.");
    }

    Ok(())
}