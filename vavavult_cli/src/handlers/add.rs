use crate::errors::CliError;
use crate::ui::prompt::confirm_action;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use vavavult::file::VaultPath; // [新增] 确保导入
use vavavult::vault::{AddFileError, AdditionTask, Vault, prepare_addition_task_standalone};
use walkdir::WalkDir;

/// 根据新的 CLI 规则构建最终的 VaultPath (用于单文件添加)
///
/// 优先级:
/// 1. `-n name` (如果提供) 总是决定最终的文件名。
/// 2. `-p path` (如果提供) 决定目标。
/// 3. `source_filename` (如果 `-n` 和 `-p` 均未提供，或 `-p` 是目录)。
///
/// @param source_filename: 从 `local_path.file_name()` 派生。
/// @param path: 来自 `-p` 选项。
/// @param name: 来自 `-n` 选项。
///
/// @return: 一个保证为 "文件路径" (非目录) 的 `VaultPath`。
fn build_target_vault_path(
    source_filename: &str,
    path: Option<String>,
    name: Option<String>,
) -> Result<VaultPath, CliError> {
    let base_path_str = path.unwrap_or_else(|| "/".to_string());
    let base_path = VaultPath::from(base_path_str.as_str());

    if let Some(filename) = name {
        // --- 优先级 1: 提供了 --name ---

        // [要求 1] 验证 --name 不包含路径分隔符
        if filename.contains('/') || filename.contains('\\') {
            return Err(CliError::InvalidName(format!(
                "Filename '{}' cannot contain path separators.",
                filename
            )));
        }

        // 将 base_path 视为目标目录
        let target_dir = if base_path.is_file() {
            // 如果 -p 是 /docs/file.txt, 我们取其父目录 /docs/
            base_path.parent().unwrap_or_else(|_| VaultPath::from("/"))
        } else {
            // 如果 -p 是 /docs/ 或 / (根)，直接使用
            base_path
        };

        // [要求 2] 使用 VaultPath::join
        Ok(target_dir.join(&filename)?)
    } else {
        // --- 优先级 2: 未提供 --name ---
        if base_path.is_file() {
            // -p 是一个完整的文件路径, 例如 `add f.txt -p /docs/report.txt`
            Ok(base_path)
        } else {
            // -p 是一个目录 (或未提供, 默认为 "/"), 使用源文件名
            // 例如 `add f.txt -p /docs/` 或 `add f.txt`
            Ok(base_path.join(source_filename)?)
        }
    }
}

/// 主处理器，根据路径类型和并行标志分发任务
pub fn handle_add(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    path: Option<String>,
    name: Option<String>,
    parallel: bool,
) -> Result<(), CliError> {
    if !local_path.exists() {
        return Err(CliError::InvalidTarget(format!(
            "Local path does not exist: {:?}",
            local_path
        )));
    }

    if local_path.is_dir() {
        // --- 处理目录添加 ---
        if name.is_some() {
            // 当添加目录时，不允许使用 --name
            return Err(CliError::InvalidCommand(
                "The --name (-n) option cannot be used when adding a directory.".to_string(),
            ));
        }

        // 目标路径（如果提供）必须是目录
        let dest_dir_path = VaultPath::from(path.unwrap_or_else(|| "/".to_string()).as_str());
        if dest_dir_path.is_file() {
            // 目标路径必须是目录
            return Err(CliError::InvalidTarget(format!(
                "When adding a directory, the target path ('{}') must be a directory (e.g., end with '/'), not a file.",
                dest_dir_path.as_str()
            )));
        }

        // `dest_dir_path` 此时保证是一个目录 (例如 /docs/ 或 /)
        if parallel {
            // 调用新的并行实现
            handle_add_directory_parallel(vault, local_path, dest_dir_path)
        } else {
            handle_add_directory_single_threaded(vault, local_path, dest_dir_path)
        }
    } else {
        // --- 处理单文件添加 ---

        // 1. 获取源文件名
        let source_filename = local_path
            .file_name()
            .ok_or_else(|| {
                CliError::InvalidTarget(
                    "Cannot add file without a filename (e.g., './').".to_string(),
                )
            })?
            .to_string_lossy();

        // 2. [V2 重构] 调用新的路径构建逻辑
        let dest_vault_path = build_target_vault_path(&source_filename, path, name)?;

        // 3. `dest_vault_path` 此时保证是一个文件路径
        handle_add_file(vault, local_path, dest_vault_path)
    }
}

/// 处理添加单个文件的逻辑
fn handle_add_file(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    dest_vault_path: VaultPath,
) -> Result<(), CliError> {
    // 库的 `add_file` 会正确处理 (因为 dest_vault_path.is_dir() 为 false)
    println!(
        "Adding file {:?} as '{}'...",
        local_path,
        dest_vault_path.as_str()
    );
    let mut vault_guard = vault.lock().unwrap();

    let hash = vault_guard.add_file(local_path, &dest_vault_path)?;
    println!("Successfully added file. Hash: {}", hash);

    Ok(())
}

/// (单线程) 处理批量添加目录的逻辑
fn handle_add_directory_single_threaded(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    dest_dir_path: VaultPath,
) -> Result<(), CliError> {
    // 1. [新增] 获取保险库中所有现有文件的路径
    println!("Fetching existing file list from vault...");
    let existing_vault_paths: std::collections::HashSet<VaultPath> = {
        let vault_guard = vault.lock().unwrap();
        vault_guard
            .list_all()?
            .into_iter()
            .map(|entry| entry.path)
            .collect()
    };
    println!(
        "Found {} files in the vault. Scanning local directory...",
        existing_vault_paths.len()
    );

    // 2. 收集所有待添加的文件, 同时过滤掉重复项
    let files_to_add: Vec<(PathBuf, VaultPath)> = WalkDir::new(local_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|entry| {
            let source_path = entry.into_path();
            let relative_path = source_path.strip_prefix(local_path).unwrap();
            let vault_path = dest_dir_path
                .join(relative_path.to_string_lossy().replace('\\', "/").as_ref())
                .unwrap();

            // 3. [新增] 检查文件是否已存在
            if existing_vault_paths.contains(&vault_path) {
                println!("Skipping duplicate file: {}", vault_path.as_str());
                None // 如果文件已存在，则将其从待添加列表中滤除
            } else {
                Some((source_path, vault_path)) // 否则，包含它
            }
        })
        .collect();

    if files_to_add.is_empty() {
        println!("No new files found to add.");
        return Ok(());
    }

    // 4. 打印文件列表
    println!(
        "\nThe following {} new files will be added:",
        files_to_add.len()
    );
    for (source, target) in &files_to_add {
        let source_display = source.to_string_lossy().replace('\\', "/");
        println!("  - \"{}\" -> {}", source_display, target.as_str());
    }

    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 5. 带进度条的单线程执行
    let pb = ProgressBar::new(files_to_add.len() as u64);
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

    for (source, target) in files_to_add {
        // 锁在循环内部获取和释放
        let mut vault_guard = vault.lock().unwrap();
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
    } // 锁在这里释放

    pb.finish_with_message("Batch add complete.");
    println!("{} succeeded, {} failed.", success_count, fail_count);
    Ok(())
}

/// (多线程) 处理批量添加目录的逻辑
fn handle_add_directory_parallel(
    vault: Arc<Mutex<Vault>>,
    local_path: &Path,
    dest_dir_path: VaultPath,
) -> Result<(), CliError> {
    // 1. [新增] 获取保险库中所有现有文件的路径
    println!("Fetching existing file list from vault...");
    let existing_vault_paths: std::collections::HashSet<VaultPath> = {
        let vault_guard = vault.lock().unwrap();
        vault_guard
            .list_all()?
            .into_iter()
            .map(|entry| entry.path)
            .collect()
    };
    println!(
        "Found {} files in the vault. Scanning local directory (parallel mode)...",
        existing_vault_paths.len()
    );

    // 2. 收集任务 (同单线程), 同时过滤掉重复项
    let files_to_add: Vec<(PathBuf, VaultPath)> = WalkDir::new(local_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|entry| {
            let source_path = entry.into_path();
            let relative_path = source_path.strip_prefix(local_path).unwrap();
            let vault_path = dest_dir_path
                .join(relative_path.to_string_lossy().replace('\\', "/").as_ref())
                .unwrap();

            // 3. [新增] 检查文件是否已存在
            if existing_vault_paths.contains(&vault_path) {
                println!("Skipping duplicate file: {}", vault_path.as_str());
                None // 如果文件已存在，则将其从待添加列表中滤除
            } else {
                Some((source_path, vault_path)) // 否则，包含它
            }
        })
        .collect();

    if files_to_add.is_empty() {
        println!("No new files found to add.");
        return Ok(());
    }

    let total_files_count = files_to_add.len();
    println!(
        "\nThe following {} new files will be added:",
        total_files_count
    );
    for (source, target) in &files_to_add {
        let source_display = source.to_string_lossy().replace('\\', "/");
        println!("  - \"{}\" -> {}", source_display, target.as_str());
    }

    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 进度条和原子计数器
    let pb = ProgressBar::new(total_files_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [Encrypting] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .map_err(|e| CliError::Unexpected(e.to_string()))?
            .progress_chars("#>-"),
    );

    let fail_count = Arc::new(AtomicUsize::new(0));

    // --- 阶段 1: 并行加密 (无锁) ---

    // 在并行循环 *之前* 获取一次数据目录路径
    // 这是一个快速的只读锁
    let storage = vault.lock().unwrap().storage.clone();

    let encryption_results: Vec<Result<AdditionTask, (String, AddFileError)>> = files_to_add
        .into_par_iter() // <-- Rayon 并行迭代
        .map(|(source_path, target_path)| {
            let pb_clone = pb.clone();

            // 调用无锁的 standalone 加密函数
            // **这里没有 vault 锁**，我们使用 clone 来的 storage 后端
            let result = prepare_addition_task_standalone(
                storage.as_ref(), // deref Arc -> &dyn StorageBackend
                &source_path,
                &target_path,
            );

            pb_clone.inc(1); // 更新进度条

            match result {
                Ok(encrypted_file) => Ok(encrypted_file),
                Err(e) => {
                    // 如果加密失败，返回错误以便报告
                    Err((target_path.as_str().to_string(), e))
                }
            }
        })
        .collect(); // 收集所有结果

    pb.finish_with_message("Encryption complete.");

    // --- 阶段 2: 收集结果 ---
    let mut files_to_commit = Vec::new();
    for result in encryption_results {
        match result {
            Ok(file) => files_to_commit.push(file),
            Err((path_str, e)) => {
                fail_count.fetch_add(1, Ordering::SeqCst);
                eprintln!("FAILED to encrypt {}: {}", path_str, e);
            }
        }
    }

    let encrypted_success_count = files_to_commit.len();

    if files_to_commit.is_empty() {
        println!("\nNo files encrypted successfully. Nothing to commit.");
        let failures = fail_count.load(Ordering::SeqCst);
        let successes = total_files_count - failures;
        println!(
            "\nBatch add complete. {} succeeded, {} failed.",
            successes, failures
        );
        return Ok(());
    }

    // --- 阶段 3: 批量提交 (一次性短时锁) ---
    println!(
        "Committing {} encrypted files to database...",
        files_to_commit.len()
    );
    {
        // **获取一次性的写锁**
        let mut vault_guard = vault.lock().unwrap();
        match vault_guard.execute_addition_tasks(files_to_commit) {
            Ok(_) => {
                println!("Batch commit successful.");
            }
            Err(e) => {
                // 如果批量提交失败 (例如，重复)，所有文件都算失败
                fail_count.fetch_add(encrypted_success_count, Ordering::SeqCst);
                eprintln!("FATAL: Batch commit failed: {}", e);
                eprintln!(
                    "This usually means one or more files already exist in the vault (e.g., duplicate content or path)."
                );
            }
        }
    } // **写锁在此处释放**

    // --- 阶段 4: 报告 ---
    let failures = fail_count.load(Ordering::SeqCst);
    let successes = total_files_count - failures;

    println!(
        "\nBatch add complete. {} succeeded, {} failed.",
        successes, failures
    );
    Ok(())
}

// [V2 新增] 单元测试模块
#[cfg(test)]
mod tests {
    use super::build_target_vault_path;
    use vavavult::file::VaultPath;

    // 辅助函数，使断言更简洁
    fn assert_path(source: &str, path: Option<&str>, name: Option<&str>, expected: &str) {
        let path_opt = path.map(|s| s.to_string());
        let name_opt = name.map(|s| s.to_string());
        let result = build_target_vault_path(source, path_opt, name_opt).unwrap();
        assert_eq!(result, VaultPath::from(expected));
    }

    // 辅助函数，用于测试错误情况
    fn assert_path_err(source: &str, path: Option<&str>, name: Option<&str>) {
        let path_opt = path.map(|s| s.to_string());
        let name_opt = name.map(|s| s.to_string());
        let result = build_target_vault_path(source, path_opt, name_opt);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_path_scenarios() {
        // 场景 1: add local.txt -> /local.txt
        assert_path("local.txt", None, None, "/local.txt");

        // 场景 2: add local.txt -p /docs/ -> /docs/local.txt
        assert_path("local.txt", Some("/docs/"), None, "/docs/local.txt");

        // 场景 3: add local.txt -p /docs/report.txt -> /docs/report.txt
        assert_path(
            "local.txt",
            Some("/docs/report.txt"),
            None,
            "/docs/report.txt",
        );

        // 场景 4: add local.txt -n new.txt -> /new.txt
        assert_path("local.txt", None, Some("new.txt"), "/new.txt");

        // 场景 5: add local.txt -p /docs/ -n new.txt -> /docs/new.txt
        assert_path(
            "local.txt",
            Some("/docs/"),
            Some("new.txt"),
            "/docs/new.txt",
        );

        // 场景 6: add local.txt -p /docs/report.txt -n new.txt -> /docs/new.txt
        // ( -n 优先级最高，-p 的文件名被忽略，只取目录)
        assert_path(
            "local.txt",
            Some("/docs/report.txt"),
            Some("new.txt"),
            "/docs/new.txt",
        );

        // 场景 7: add local.txt -p / -n new.txt -> /new.txt
        assert_path("local.txt", Some("/"), Some("new.txt"), "/new.txt");
    }

    #[test]
    fn test_build_path_invalid_name() {
        assert_path_err("local.txt", None, Some("invalid/name.txt"));
        assert_path_err("local.txt", Some("/docs/"), Some("invalid/name.txt"));
        assert_path_err("local.txt", None, Some("invalid\\name.txt"));
    }
}
