use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

/// 处理文件重命名命令
pub fn handle_file_rename(
    vault: &mut Vault,
    vault_name: Option<String>,
    sha256: Option<String>,
    new_name: &str,
) -> Result<(), Box<dyn Error>> {
    // 1. 查找要重命名的文件
    let file_entry = find_file_entry(vault, vault_name, sha256)?;
    let old_name = file_entry.name.clone(); // 保存旧名称用于输出

    println!("Renaming '{}' to '{}'...", old_name, new_name);

    // 2. 调用核心库的 rename_file 方法
    // 注意：这里我们仍然使用旧的 &str API
    match vault.rename_file(&file_entry.sha256sum, new_name) {
        Ok(_) => {
            println!("File successfully renamed.");
            Ok(())
        }
        Err(e) => {
            // 将 vavavult::vault::UpdateError 转换为 Box<dyn Error>
            Err(format!("Error renaming file: {}", e).into())
        }
    }
}