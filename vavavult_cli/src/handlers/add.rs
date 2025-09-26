use std::error::Error;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use vavavult::vault::Vault;
use crate::utils::confirm_action;

/// 主处理器，根据路径类型分发任务
pub fn handle_add(vault: &mut Vault, local_path: &Path, file_name: Option<String>, dest_dir: Option<String>) -> Result<(), Box<dyn Error>> {
    if !local_path.exists() {
        return Err(format!("Path does not exist: {:?}", local_path).into());
    }

    if local_path.is_dir() {
        // 如果源是目录，则不允许使用 -n 参数
        if file_name.is_some() {
            return Err("The --name (-n) option can only be used when adding a single file, not a directory.".into());
        }
        handle_add_directory(vault, local_path, dest_dir)
    } else {
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
fn handle_add_file(vault: &mut Vault, local_path: &Path, file_name: Option<String>, dest_dir: Option<String>) -> Result<(), Box<dyn Error>> {
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
    match vault.add_file(local_path, Some(&vault_path)) {
        Ok(hash) => println!("Successfully added file. Hash: {}", hash),
        Err(e) => eprintln!("Error adding file: {}", e),
    }
    Ok(())
}

/// 处理批量添加目录的逻辑
fn handle_add_directory(vault: &mut Vault, local_path: &Path, dest_dir: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?}...", local_path);

    // 1. 收集所有待添加的文件
    let mut files_to_add = Vec::new();
    for entry in WalkDir::new(local_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let source_path = entry.into_path();
            // 计算文件相对于扫描根目录的路径
            let relative_path = source_path.strip_prefix(local_path)?.to_path_buf();
            let relative_path_str = relative_path.to_string_lossy().to_string();

            // 将此相对路径作为文件名，与目标目录 -d 结合
            let vault_path = build_vault_path(dest_dir.clone(), relative_path_str);

            files_to_add.push((source_path, vault_path));
        }
    }

    if files_to_add.is_empty() {
        println!("No files found to add in the directory.");
        return Ok(());
    }

    // 2. 向用户展示并请求确认
    println!("The following {} files will be added:", files_to_add.len());
    for (source, target) in &files_to_add {
        println!("  - {:?} -> {}", source, target);
    }
    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 3. 执行添加
    let mut success_count = 0;
    let mut fail_count = 0;
    for (source, target) in files_to_add {
        print!("Adding {:?}...", source);
        io::stdout().flush()?;
        match vault.add_file(&source, Some(&target)) {
            Ok(_) => {
                println!(" OK");
                success_count += 1;
            }
            Err(e) => {
                println!(" FAILED ({})", e);
                fail_count += 1;
            }
        }
    }

    println!("\nBatch add complete. {} succeeded, {} failed.", success_count, fail_count);
    Ok(())
}