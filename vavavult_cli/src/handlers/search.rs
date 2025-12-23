use crate::errors::CliError;
use crate::utils::{print_file_details, print_recursive_file_item};
use vavavult::vault::Vault;

/// 处理 'search' (或 'find') 命令
pub fn handle_search(
    vault: &Vault,
    keyword: &str,
    long: bool, // -l
) -> Result<(), CliError> {
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

    // 检查 colorfulTag 特性是否启用
    let colors_enabled = vault.is_feature_enabled("colorfulTag").unwrap_or(false);

    if long {
        // 搜索的 -l (详细)
        for file in &found_files {
            print_file_details(file, colors_enabled); // (风格 3)
        }
        if !found_files.is_empty() {
            println!("----------------------------------------");
        }
    } else {
        // 搜索的默认 (非详细)
        for file in &found_files {
            print_recursive_file_item(file, colors_enabled); // (风格 1)
        }
    }

    Ok(())
}
