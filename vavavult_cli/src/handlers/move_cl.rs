use std::error::Error;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

/// 处理 'mv' (Move) 命令
pub fn handle_move(
    vault: &mut Vault,
    target: &str,
    destination: String,
) -> Result<(), Box<dyn Error>> {

    // 1. 查找源文件
    // 使用 find_file_entry，它会自动识别 path/hash
    let file_entry = find_file_entry(vault, target)?;
    let old_path = file_entry.path.clone();

    // 2. 检查目标是“纯文件名”还是“路径”
    if !destination.contains('/') && !destination.contains('\\') {
        // --- 案例 A: 纯文件名 (e.g., "new.txt") ---
        println!("Renaming (in-place) '{}' to '{}'...", old_path, destination);
        vault.rename_file_inplace(&file_entry.sha256sum, &destination)?;
        println!("File successfully renamed.");

    } else {
        // --- 案例 B: 路径 (e.g., "/docs/" or "/docs/new.txt") ---
        let target_vault_path = VaultPath::from(destination.as_str());
        println!("Moving '{}' to '{}'...", old_path, target_vault_path);
        vault.move_file(&file_entry.sha256sum, &target_vault_path)?;
        println!("File successfully moved.");
    }

    Ok(())
}