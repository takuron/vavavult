use std::env;
use std::error::Error;
use std::path::Path;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

pub fn handle_open(vault: &Vault, vault_name: Option<String>, sha256: Option<String>) -> Result<(), Box<dyn Error>> {
    let file_entry = find_file_entry(vault, vault_name, sha256)?;

    // 1. 创建一个临时文件路径
    let temp_dir = env::temp_dir();
    let file_name = Path::new(&file_entry.path).file_name().unwrap_or_default();
    let temp_path = temp_dir.join(file_name);

    // 2. 提取文件到临时路径
    println!("Extracting a temporary copy to {:?}...", temp_path);
    vault.extract_file(&file_entry.sha256sum, &temp_path)?;

    // 3. 使用 opener 打开文件
    match opener::open(&temp_path) {
        Ok(_) => {
            println!("Successfully opened '{}'.", file_entry.path);
            println!("NOTE: You are viewing a temporary copy. Any changes will NOT be saved to the vault.");
            Ok(())
        }
        Err(e) => {
            Err(format!("Failed to open file with default application: {}", e).into())
        }
    }
}