use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use walkdir::WalkDir;
use vavavult::vault::{AddFileError, Vault};
use vavavult::file::VaultPath; // [新增] 确保导入
use crate::utils::confirm_action;

/// [新增] 辅助函数：根据 CLI 参数构建最终的 VaultPath
///
/// 逻辑:
/// 1. `dest_dir` (e.g., "/docs/")
/// 2. `file_name` (e.g., "report.txt")
///
/// - dir & name -> "/docs/report.txt"
/// - dir only -> "/docs/" (库将附加源文件名)
/// - name only -> "/report.txt" (库将其视为文件路径)
/// - neither -> "/" (库将附加源文件名)
fn build_vault_path_from_cli(
    dest_dir: Option<String>,
    file_name: Option<String>,
) -> Result<VaultPath, Box<dyn Error>> {
    let base_path = dest_dir.unwrap_or_else(|| "/".to_string());

    // 规范化基础路径
    let mut dir_path = VaultPath::from(base_path.as_str());

    if let Some(name) = file_name {
        // 如果提供了 -n，将其连接到路径
        // 如果 dir_path 是 "/docs/" (目录), 结果是 "/docs/name.txt"
        // 如果 dir_path 是 "/docs" (文件), join 会失败
        if !dir_path.is_dir() {
            // 用户可能输入了 -d /docs (被解析为文件)
            // 我们将其强制转换为目录以便 join
            dir_path = VaultPath::from(format!("{}/", dir_path.as_str()).as_str());
        }
        Ok(dir_path.join(&name)?)
    } else {
        // 如果只提供了 -d 或什么都没提供，返回路径本身
        // -d /docs/ -> /docs/ (目录)
        // -d /docs -> /docs (文件，库会报错，除非是单文件且local_path.is_dir()为false)
        // (无参数) -> / (目录)
        Ok(dir_path)
    }
}


/// 主处理器，根据路径类型和并行标志分发任务
pub fn handle_add(vault: Arc<Mutex<Vault>>, local_path: &Path, file_name: Option<String>, dest_dir: Option<String>, parallel: bool) -> Result<(), Box<dyn Error>> {
    if !local_path.exists() {
        return Err(format!("Path does not exist: {:?}", local_path).into());
    }

    // [修改] 在这里构建 VaultPath
    let dest_vault_path = build_vault_path_from_cli(dest_dir.clone(), file_name.clone())?;

    if local_path.is_dir() {
        if file_name.is_some() {
            return Err("The --name (-n) option can only be used when adding a single file, not a directory.".into());
        }
        // `dest_vault_path` 此时必须是目录 (e.g., "/docs/" 或 "/")
        if !dest_vault_path.is_dir() {
            return Err(format!("When adding a directory, the destination path ('{}') must be a directory (end with '/').", dest_vault_path.as_str()).into());
        }

        if parallel {
            handle_add_directory_parallel(vault, local_path, dest_vault_path) // [修改] 传递 VaultPath
        } else {
            handle_add_directory_single_threaded(vault, local_path, dest_vault_path) // [修改] 传递 VaultPath
        }
    } else {
        // `dest_vault_path` 此时可以是文件 (e.g., "/report.txt") 或目录 (e.g., "/docs/")
        // 库的 resolve_final_path 会处理这两种情况
        handle_add_file(vault, local_path, dest_vault_path) // [修改] 传递 VaultPath
    }
}

/// 处理添加单个文件的逻辑
fn handle_add_file(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    dest_vault_path: VaultPath // [修改] 接收 VaultPath
) -> Result<(), Box<dyn Error>> {

    println!("Adding file {:?} as '{}'...", local_path, dest_vault_path.as_str());
    let mut vault_guard = vault.lock().unwrap();

    // [修改] 调用新的 add_file API
    match vault_guard.add_file(local_path, &dest_vault_path) {
        Ok(hash) => println!("Successfully added file. Hash: {}", hash),
        Err(e) => eprintln!("Error adding file: {}", e),
    }
    Ok(())
}

/// (单线程) 处理批量添加目录的逻辑
fn handle_add_directory_single_threaded(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    dest_dir_path: VaultPath // [修改] 接收 VaultPath (保证是目录)
) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?}...", local_path);

    // 1. 收集所有待添加的文件
    let files_to_add: Vec<_> = WalkDir::new(local_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|entry| {
            let source_path = entry.into_path();
            // [修改] 使用 VaultPath::join
            let relative_path = source_path.strip_prefix(local_path).unwrap();
            let vault_path = dest_dir_path.join(relative_path.to_string_lossy().replace('\\', "/").as_ref()).unwrap();
            (source_path, vault_path)
        })
        .collect();

    if files_to_add.is_empty() {
        println!("No files found to add in the directory.");
        return Ok(());
    }

    // 2. 打印文件列表
    println!("The following {} files will be added:", files_to_add.len());
    for (source, target) in &files_to_add {
        let source_display = source.to_string_lossy().replace('\\', "/");
        println!("  - \"{}\" -> {}", source_display, target.as_str()); // [修改]
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
        // [修改] 调用新的 add_file API
        match vault_guard.add_file(&source, &target) {
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

// (多线程) 处理批量添加目录的逻辑
fn handle_add_directory_parallel(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    dest_dir_path: VaultPath // 接收 VaultPath (保证是目录)
) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?} (parallel mode)...", local_path);

    let files_to_add: Vec<_> = WalkDir::new(local_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|entry| {
            let source_path = entry.into_path();
            let relative_path = source_path.strip_prefix(local_path).unwrap();
            let vault_path = dest_dir_path.join(relative_path.to_string_lossy().replace('\\', "/").as_ref()).unwrap();
            (source_path, vault_path) // (PathBuf, VaultPath)
        })
        .collect();

    if files_to_add.is_empty() {
        println!("No files found in the directory.");
        return Ok(());
    }

    println!("The following {} files will be added:", files_to_add.len());
    for (source, target) in &files_to_add {
        let source_display = source.to_string_lossy().replace('\\', "/");
        println!("  - \"{}\" -> {}", source_display, target.as_str());
    }

    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 在 files_to_add 被移动之前，保存总数
    let total_files_count = files_to_add.len();

    // 进度条和原子计数器
    let pb = ProgressBar::new(total_files_count as u64); // [修改] 使用 total_files_count
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [Encrypting] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
        .progress_chars("#>-"));
    let fail_count = Arc::new(AtomicUsize::new(0));

    // --- 阶段 1: 并行加密 ---
    let encryption_results: Vec<_> = files_to_add // files_to_add 在这里被 move
        .into_par_iter()
        .map(|(source, target_path)| {
            let vault_guard = vault.lock().unwrap();
            let pb_clone = pb.clone();
            let fail_count_clone = Arc::clone(&fail_count);

            match vault_guard.encrypt_file_for_add(&source, &target_path) {
                Ok(encrypted_file) => {
                    pb_clone.inc(1);
                    Some(encrypted_file)
                }
                Err(e) => {
                    fail_count_clone.fetch_add(1, Ordering::SeqCst);
                    pb_clone.println(format!("FAILED to encrypt {}: {}", target_path.as_str(), e));
                    pb_clone.inc(1);
                    None
                }
            }
        })
        .collect();

    pb.finish_with_message("Encryption complete.");

    // 过滤掉加密失败的文件
    let files_to_commit: Vec<_> = encryption_results.into_iter().filter_map(|r| r).collect();
    let encrypted_success_count = files_to_commit.len();

    if files_to_commit.is_empty() {
        println!("\nNo files to commit.");
        // [修正] 确保即使没有文件提交，也打印正确的最终计数
        let failures = fail_count.load(Ordering::SeqCst);
        let successes = total_files_count - failures;
        println!("\nBatch add complete. {} succeeded, {} failed.", successes, failures);
        return Ok(());
    }

    // --- 阶段 2: 批量提交 (单线程) ---
    println!("Committing {} files to database...", files_to_commit.len());
    {
        let mut vault_guard = vault.lock().unwrap();
        match vault_guard.commit_add_files(files_to_commit) {
            Ok(_) => {
                println!("Batch commit successful.");
            }
            Err(e) => {
                // 如果批量提交失败，将所有尝试提交的文件计为失败
                fail_count.fetch_add(encrypted_success_count, Ordering::SeqCst);
                eprintln!("FATAL: Batch commit failed: {}", e);
            }
        }
    }

    // 从原子计数器加载最终结果
    let failures = fail_count.load(Ordering::SeqCst);
    // 使用 total_files_count
    let successes = total_files_count - failures;

    println!("\nBatch add complete. {} succeeded, {} failed.", successes, failures);
    Ok(())
}