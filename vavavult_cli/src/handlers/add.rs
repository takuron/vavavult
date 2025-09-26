use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;
use rayon::prelude::*;
use vavavult::vault::{Vault};
use crate::utils::confirm_action;

/// 主处理器，根据路径类型和并行标志分发任务
pub fn handle_add(vault: Arc<Mutex<Vault>>, local_path: &Path, file_name: Option<String>, dest_dir: Option<String>, parallel: bool) -> Result<(), Box<dyn Error>> {
    if !local_path.exists() {
        return Err(format!("Path does not exist: {:?}", local_path).into());
    }

    if local_path.is_dir() {
        if file_name.is_some() {
            return Err("The --name (-n) option can only be used when adding a single file, not a directory.".into());
        }
        // 根据 parallel 标志调用不同的目录处理器
        if parallel {
            handle_add_directory_parallel(vault, local_path, dest_dir)
        } else {
            handle_add_directory_single_threaded(vault, local_path, dest_dir)
        }
    } else {
        // 单文件添加总是单线程
        handle_add_file(vault, local_path, file_name, dest_dir)
    }
}

/// 辅助函数：根据目标目录和文件名构建最终的、标准化的 vault 路径
fn build_vault_path(dest_dir: Option<String>, file_name: String) -> String {
    let mut path = PathBuf::new();
    if let Some(dir) = dest_dir {
        path.push(dir);
    }
    path.push(file_name);
    // 确保最终路径使用正斜杠
    path.to_string_lossy().replace('\\', "/")
}

/// 处理添加单个文件的逻辑
fn handle_add_file(vault: Arc<Mutex<Vault>>, local_path: &Path, file_name: Option<String>, dest_dir: Option<String>) -> Result<(), Box<dyn Error>> {
    // 确定最终文件名：如果 -n 提供了，就用它；否则，从源路径提取。
    let final_file_name = file_name.unwrap_or_else(|| {
        local_path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown_file")
            .to_string()
    });

    // 构建在 vault 中的完整路径
    let vault_path = build_vault_path(dest_dir, final_file_name);

    println!("Adding file {:?} as '{}'...", local_path, vault_path);
    let mut vault_guard = vault.lock().unwrap();
    match vault_guard.add_file(local_path, Some(&vault_path)) {
        Ok(hash) => println!("Successfully added file. Hash: {}", hash),
        Err(e) => eprintln!("Error adding file: {}", e),
    }
    Ok(())
}

/// (单线程) 处理批量添加目录的逻辑
fn handle_add_directory_single_threaded(vault: Arc<Mutex<Vault>>, local_path: &Path, dest_dir: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?}...", local_path);

    // 1. 收集所有待添加的文件 (与之前逻辑相同)
    let files_to_add: Vec<_> = WalkDir::new(local_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|entry| {
            let source_path = entry.into_path();
            let relative_path = source_path.strip_prefix(local_path).unwrap().to_path_buf();
            let vault_path = build_vault_path(dest_dir.clone(), relative_path.to_string_lossy().to_string());
            (source_path, vault_path)
        })
        .collect();

    if files_to_add.is_empty() {
        println!("No files found to add in the directory.");
        return Ok(());
    }

    // 2. 恢复打印文件列表的逻辑
    println!("The following {} files will be added:", files_to_add.len());
    // --- 修改: 在打印前统一路径分隔符 ---
    for (source, target) in &files_to_add {
        let source_display = source.to_string_lossy().replace('\\', "/");
        println!("  - \"{}\" -> {}", source_display, target);
    }

    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 3. 带进度条的单线程执行
    let pb = ProgressBar::new(files_to_add.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
        .progress_chars("#>-"));

    let mut success_count = 0;
    let mut fail_count = 0;

    for (source, target) in files_to_add {
        let mut vault_guard = vault.lock().unwrap();
        match vault_guard.add_file(&source, Some(&target)) {
            Ok(_) => {
                success_count += 1;
            }
            Err(e) => {
                fail_count += 1;
                pb.println(format!("FAILED to add {:?}: {}", source, e));
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("Batch add complete.");
    println!("{} succeeded, {} failed.", success_count, fail_count);
    Ok(())
}

fn handle_add_directory_parallel(vault: Arc<Mutex<Vault>>, local_path: &Path, dest_dir: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?}...", local_path);

    let files_to_add: Vec<_> = WalkDir::new(local_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|entry| {
            let source_path = entry.into_path();
            let relative_path = source_path.strip_prefix(local_path).unwrap().to_path_buf();
            let vault_path_str = build_vault_path(dest_dir.clone(), relative_path.to_string_lossy().to_string());
            (source_path, vault_path_str)
        })
        .collect();

    if files_to_add.is_empty() {
        println!("No files found in the directory.");
        return Ok(());
    }

    println!("The following {} files will be added:", files_to_add.len());
    // --- 修改: 在打印前统一路径分隔符 ---
    for (source, target) in &files_to_add {
        let source_display = source.to_string_lossy().replace('\\', "/");
        println!("  - \"{}\" -> {}", source_display, target);
    }
    
    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // --- 修改: 统一的进度条和原子计数器 ---
    let pb = ProgressBar::new(files_to_add.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
        .progress_chars("#>-"));

    let success_count = AtomicUsize::new(0);
    let fail_count = AtomicUsize::new(0);

    files_to_add
        .into_par_iter()
        .for_each(|(source, target_name)| {
            // 1. 准备阶段 (只读锁)
            let transaction_result = {
                let vault_guard = vault.lock().unwrap();
                vault_guard.prepare_add_transaction(&source)
            };

            // 2. 提交阶段 (写锁)
            match transaction_result {
                Ok(transaction) => {
                    let mut vault_guard = vault.lock().unwrap();
                    match vault_guard.commit_add_transaction(transaction, &target_name) {
                        Ok(_) => {
                            success_count.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => {
                            fail_count.fetch_add(1, Ordering::SeqCst);
                            pb.println(format!("FAILED to commit {}: {}", target_name, e));
                        }
                    }
                }
                Err(e) => {
                    fail_count.fetch_add(1, Ordering::SeqCst);
                    pb.println(format!("FAILED to prepare {:?}: {}", source, e));
                }
            }
            pb.inc(1);
        });

    pb.finish_with_message("Batch add complete.");

    // 从原子计数器加载最终结果
    let successes = success_count.load(Ordering::SeqCst);
    let failures = fail_count.load(Ordering::SeqCst);

    println!("\nBatch add complete. {} succeeded, {} failed.", successes, failures);
    Ok(())
}