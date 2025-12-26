use crate::core::helpers::{Target, find_file_entry, identify_target};
use crate::errors::CliError;
use std::env;
use vavavult::vault::Vault;

pub fn handle_open(vault: &Vault, target: &str) -> Result<(), CliError> {
    // 使用 identify_target 进行预检查
    if let Ok(Target::Path(p)) = identify_target(target) {
        if !p.is_file() {
            return Err(CliError::InvalidTarget(format!(
                "Cannot open '{}': Path is a directory, not a file.",
                p
            )));
        }
    }

    // 查找文件 (自动处理 Path 或 Hash)
    let file_entry = find_file_entry(vault, target)?;

    // 1. 创建一个临时文件路径
    let temp_dir = env::temp_dir();
    let file_name = file_entry.path.file_name().unwrap_or_default();
    let temp_path = temp_dir.join(file_name);

    // 2. 提取文件到临时路径
    println!("Extracting a temporary copy to {:?}...", temp_path);
    vault.extract_file(&file_entry.sha256sum, &temp_path)?;

    // 3. 使用 opener 打开文件
    match opener::open(&temp_path) {
        Ok(_) => {
            println!("Successfully opened '{}'.", file_entry.path);
            println!(
                "NOTE: You are viewing a temporary copy. Any changes will NOT be saved to the vault."
            );
            Ok(())
        }
        Err(e) => Err(CliError::Unexpected(format!(
            "Failed to open file with default application: {}",
            e
        ))),
    }
}
