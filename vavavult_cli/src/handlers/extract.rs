use std::error::Error;
use std::{fs, io};
use std::io::Write;
use std::path::{Path, PathBuf};
use vavavult::file::FileEntry;
use vavavult::vault::Vault;
use crate::utils::{confirm_action, determine_output_path, find_file_entry};

pub fn handle_extract(vault: &mut Vault,vault_name:Option<String>, sha256:Option<String>, dir_path:Option<String>, destination:PathBuf, output_name:Option<String>, delete:bool) -> Result<(), Box<dyn Error>> {
    if let Some(dir) = dir_path {
        // 新增：处理目录提取
        Ok(handle_extract_directory(vault, &dir, &destination, delete)?)
    } else {
        // 现有：处理单文件提取
        Ok(handle_extract_single_file(vault, vault_name, sha256, &destination, output_name, delete)?)
    }
}

/// 处理提取单个文件的逻辑
fn handle_extract_single_file(vault: &mut Vault, vault_name: Option<String>, sha256: Option<String>, destination: &Path, output_name: Option<String>, delete: bool) -> Result<(), Box<dyn Error>> {
    let file_entry = find_file_entry(vault, vault_name, sha256)?;
    let final_path = determine_output_path(&file_entry, destination.to_path_buf(), output_name);

    if delete {
        if !confirm_action(&format!(
            "This will extract '{}' to {:?} and then PERMANENTLY DELETE it. Are you sure?",
            file_entry.name, final_path
        ))? {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    println!("Extracting '{}' to {:?}...", file_entry.name, final_path);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }
    vault.extract_file(&file_entry.sha256sum, &final_path)?;
    println!("File extracted successfully.");

    if delete {
        println!("Deleting '{}' from vault...", file_entry.name);
        vault.remove_file(&file_entry.sha256sum)?;
        println!("File successfully deleted from vault.");
    }
    Ok(())
}

/// 处理提取整个目录的逻辑
fn handle_extract_directory(vault: &mut Vault, dir_path: &str, destination: &Path, delete: bool) -> Result<(), Box<dyn Error>> {
    println!("Scanning vault directory '{}' for extraction...", dir_path);
    let files_to_extract = get_all_files_recursively(vault, dir_path)?;

    if files_to_extract.is_empty() {
        println!("No files found in vault directory '{}'.", dir_path);
        return Ok(());
    }

    println!("The following {} files will be extracted to {:?}", files_to_extract.len(), destination);
    if delete {
        println!("WARNING: The original files will be PERMANENTLY DELETED from the vault after extraction.");
    }
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    let mut success_count = 0;
    let mut fail_count = 0;
    for entry in &files_to_extract {
        let relative_path = Path::new(&entry.name).strip_prefix(dir_path).unwrap_or(Path::new(&entry.name));
        let final_path = destination.join(relative_path);

        print!("Extracting {} -> {:?} ...", entry.name, final_path);
        io::stdout().flush()?;

        if let Some(parent) = final_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                println!(" FAILED (could not create local directory: {})", e);
                fail_count += 1;
                continue;
            }
        }

        match vault.extract_file(&entry.sha256sum, &final_path) {
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

    println!("\nExtraction complete. {} succeeded, {} failed.", success_count, fail_count);

    if delete && success_count > 0 {
        println!("\nDeleting {} extracted files from vault...", success_count);
        if !confirm_action("Confirm deletion of successfully extracted files?")? {
            println!("Deletion cancelled.");
            return Ok(());
        }
        for entry in files_to_extract.iter().filter(|_| fail_count == 0) { // Simple filter for now
            match vault.remove_file(&entry.sha256sum) {
                Ok(_) => println!("Deleted {}.", entry.name),
                Err(e) => eprintln!("Failed to delete {}: {}", entry.name, e),
            }
        }
    }

    Ok(())
}

/// 递归地获取一个 vault 目录下的所有文件
fn get_all_files_recursively(vault: &Vault, dir_path: &str) -> Result<Vec<FileEntry>, Box<dyn Error>> {
    let mut all_files = Vec::new();
    let mut dirs_to_scan = vec![dir_path.to_string()];

    while let Some(current_dir) = dirs_to_scan.pop() {
        let result = vault.list_by_path(&current_dir)?;
        all_files.extend(result.files);
        for subdir in result.subdirectories {
            let full_subdir_path = Path::new(&current_dir).join(subdir).to_string_lossy().into_owned();
            dirs_to_scan.push(full_subdir_path);
        }
    }
    Ok(all_files)
}