use std::env;
use std::error::Error;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

pub fn handle_open(vault: &Vault, path: Option<String>, hash: Option<String>) -> Result<(), Box<dyn Error>> {

    // [新增] 检查路径是否为目录
    if let Some(p) = &path {
        let vault_path = VaultPath::from(p.as_str());
        if !vault_path.is_file() {
            // [新增] 如果是目录 (例如 "/docs/" 或 "/")，立即报错
            return Err(format!(
                "Cannot open '{}': Path is a directory, not a file.",
                vault_path
            ).into());
        }
        // 如果 vault_path 是文件路径 (例如 "/report.txt")，则继续
    }
    // (如果提供了 hash，则跳过此检查，直接查找)

    // 调用 find_file_entry。
    // 如果路径是文件 (如 "/report.txt") 但不存在，find_file_entry 会正确返回 "Not Found"。
    let file_entry = find_file_entry(vault, path, hash)?;
    // --- [END_MODIFICATION] ---


    // 1. 创建一个临时文件路径
    let temp_dir = env::temp_dir();
    // 使用 file_entry.path (这是一个 VaultPath) 来获取文件名
    let file_name = file_entry.path.file_name().unwrap_or_default();
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