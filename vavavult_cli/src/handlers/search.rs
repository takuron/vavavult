use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::{print_file_details, print_recursive_file_item};

/// 处理 'search' (或 'find') 命令
pub fn handle_search(
    vault: &Vault,
    keyword: &str,
    long: bool, // -l
) -> Result<(), Box<dyn Error>> {

    let found_files = vault.find_by_keyword(keyword)?;

    if found_files.is_empty() {
        println!("No files found matching '{}' (in name or tags).", keyword);
        return Ok(());
    }

    println!(
        "Found {} file(s) matching '{}' (in name or tags):",
        found_files.len(),
        keyword
    );

    if long {
        // 搜索的 -l (详细)
        for file in &found_files {
            print_file_details(file); // (风格 3)
        }
        if !found_files.is_empty() {
            println!("----------------------------------------");
        }
    } else {
        // 搜索的默认 (非详细)
        for file in &found_files {
            print_recursive_file_item(file); // (风格 1)
        }
    }

    Ok(())
}