use std::error::Error;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

/// 处理 'mv' (Move) 命令
pub fn handle_move(
    vault: &mut Vault,
    path: Option<String>,
    hash: Option<String>,
    destination: String,
) -> Result<(), Box<dyn Error>> {

    // 1. 查找源文件
    let file_entry = find_file_entry(vault, path, hash)?;
    let old_path = file_entry.path.clone();

    // 2. 检查目标是“纯文件名”还是“路径”
    if !destination.contains('/') && !destination.contains('\\') {
        // --- 案例 A: 纯文件名 (e.g., "new.txt") ---
        // 这是“就地重命名”
        println!("Renaming (in-place) '{}' to '{}'...", old_path, destination);

        // 调用 `rename_file_inplace`
        vault.rename_file_inplace(&file_entry.sha256sum, &destination)?;

        println!("File successfully renamed.");

    } else {
        // --- 案例 B: 路径 (e.g., "/docs/" or "/docs/new.txt") ---
        // 这是“移动”

        // 将目标字符串转换为 `VaultPath`
        let target_vault_path = VaultPath::from(destination.as_str());

        println!("Moving '{}' to '{}'...", old_path, target_vault_path);

        // 调用 `move_file`
        // 库 API 会自动处理目标是目录还是文件
        vault.move_file(&file_entry.sha256sum, &target_vault_path)?;

        println!("File successfully moved.");
    }

    Ok(())
}