use crate::errors::CliError;
use crate::utils::{
    get_all_files_recursively, print_dir_details, print_directory_entry, print_file_details,
    print_recursive_file_item,
};
use vavavult::file::VaultPath;
use vavavult::vault::{DirectoryEntry, QueryResult, Vault};

/// 匹配新的 'ls' 风格命令和新的打印风格
pub fn handle_list(
    vault: &Vault,
    path: Option<String>,
    long: bool,
    recursive: bool,
) -> Result<(), CliError> {
    let target_path_str = path.unwrap_or_else(|| "/".to_string());
    let target_vault_path = VaultPath::from(target_path_str.as_str());

    if target_vault_path.is_file() {
        // ls 命令现在只接受目录。如果传入文件路径，则报错。
        // 这与 open 命令的逻辑保持一致。
        return Err(CliError::InvalidTarget(format!(
            "Cannot list '{}': Path is a file, not a directory. 'ls' is for directories.",
            target_vault_path
        )));
    }
    // 检查 colorfulTag 特性是否启用
    let colors_enabled = vault.is_feature_enabled("colorfulTag").unwrap_or(false);

    // 检查 `ls` 的目标是文件还是目录
    if target_vault_path.is_file() {
        // `ls /path/to/file.txt` (递归标志无效)
        match vault.find_by_path(&target_vault_path)? {
            QueryResult::Found(entry) => {
                if long {
                    print_file_details(&entry, colors_enabled); // (风格 3)
                } else {
                    print_recursive_file_item(&entry, colors_enabled); // (风格 1)
                }
            }
            QueryResult::NotFound => {
                println!("Error: File not found at path '{}'", target_vault_path);
            }
        }
        println!("----------------------------------------");
        return Ok(());
    }

    // `ls` 的目标是目录
    if !recursive {
        // 只有在非递归时才打印这个 (递归会打印每个子目录)
        println!("Contents of '{}':", target_vault_path);
    }

    if recursive {
        // --- `ls -R` (递归) ---
        if !long {
            println!(
                "Recursively listing contents of '{}' (Files only):",
                target_vault_path
            );
        }
        let all_files = get_all_files_recursively(vault, target_vault_path.as_str())?;
        if all_files.is_empty() {
            println!("(empty)");
            return Ok(());
        }

        for file in &all_files {
            if long {
                print_file_details(file, colors_enabled); // (风格 3)
            } else {
                print_recursive_file_item(file, colors_enabled); // (风格 1)
            }
        }
        if long && !all_files.is_empty() {
            println!("----------------------------------------");
        }
    } else {
        // --- `ls` (默认，非递归) ---
        let entries = vault.list_by_path(&target_vault_path)?;

        if entries.is_empty() {
            println!("(empty)");
            return Ok(());
        }

        for entry in &entries {
            if long {
                // `ls -l`
                match entry {
                    DirectoryEntry::Directory(path) => print_dir_details(path),
                    DirectoryEntry::File(file_entry) => {
                        print_file_details(file_entry, colors_enabled)
                    }
                }
            } else {
                // `ls`
                // 使用新的无查询打印函数
                print_directory_entry(entry, colors_enabled);
            }
        }
        if long && !entries.is_empty() {
            println!("----------------------------------------");
        }
    }

    Ok(())
}
