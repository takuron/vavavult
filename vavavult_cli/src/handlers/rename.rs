use std::error::Error;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

/// 处理文件重命名命令
pub fn handle_file_rename(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
    new_name_str: &str,
) -> Result<(), Box<dyn Error>> {
    // 1. 查找要重命名的文件 (不变)
    let file_entry = find_file_entry(vault, vault_name, sha256)?;
    let old_name = file_entry.path.clone();

    // 2. 将输入的字符串转换为 VaultPath (不变)
    let new_vault_path = VaultPath::from(new_name_str);

    println!("Renaming '{}' to '{}'...", old_name, new_vault_path.as_str());

    //    API 签名 (move_file(&mut self, hash: &VaultHash, target_path: &VaultPath))
    match vault.move_file(&file_entry.sha256sum, &new_vault_path) {
        Ok(_) => {
            println!("File successfully renamed.");
            Ok(())
        }
        Err(e) => {
            Err(format!("Error renaming file: {}", e).into())
        }
    }
}