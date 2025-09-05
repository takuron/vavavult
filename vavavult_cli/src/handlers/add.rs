use std::error::Error;
use std::io;
use std::io::Write;
use std::path::Path;
use walkdir::WalkDir;
use vavavult::vault::Vault;
use crate::utils::confirm_action;

pub fn handle_add(vault: &Vault, local_path: &Path, vault_name: Option<String>) -> Result<(), Box<dyn Error>> {
    if !local_path.exists() {
        return Err(format!("Path does not exist: {:?}", local_path).into());
    }

    if local_path.is_dir() {
        handle_add_directory(vault, local_path, vault_name)
    } else {
        handle_add_file(vault, local_path, vault_name)
    }
}

/// 处理添加单个文件的逻辑
fn handle_add_file(vault: &Vault, local_path: &Path, vault_name: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Adding file {:?}...", local_path);
    match vault.add_file(local_path, vault_name.as_deref()) {
        Ok(hash) => println!("Successfully added file. Hash: {}", hash),
        Err(e) => eprintln!("Error adding file: {}", e),
    }
    Ok(())
}

/// 处理批量添加目录的逻辑
fn handle_add_directory(vault: &Vault, local_path: &Path, prefix: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?}...", local_path);

    // 1. 收集所有待添加的文件
    let mut files_to_add = Vec::new();
    for entry in WalkDir::new(local_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let source_path = entry.into_path();
            // 计算文件相对于根目录的路径
            let relative_path = source_path.strip_prefix(local_path)?.to_path_buf();

            // 构建在 vault 中的目标路径
            let vault_target_path = if let Some(p) = &prefix {
                // 如果有前缀，则拼接
                Path::new(p).join(&relative_path)
            } else {
                // 否则直接使用相对路径
                relative_path
            };

            files_to_add.push((source_path, vault_target_path));
        }
    }

    if files_to_add.is_empty() {
        println!("No files found to add in the directory.");
        return Ok(());
    }

    // 2. 向用户展示并请求确认
    println!("The following {} files will be added:", files_to_add.len());
    for (source, target) in &files_to_add {
        println!("  - {:?} -> {}", source, target.display());
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
        match vault.add_file(&source, target.to_str()) {
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