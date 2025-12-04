use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::find_file_entry;

/// 处理文件重命名命令
pub fn handle_file_rename(
    vault: &mut Vault,
    target: &str,
    new_name: &str,
) -> Result<(), Box<dyn Error>> {

    // 1. 查找要重命名的文件
    let file_entry = find_file_entry(vault, target)?;
    let old_name = file_entry.path.clone();

    // 2. 验证 new_name 是纯文件名
    if new_name.contains('/') || new_name.contains('\\') {
        return Err(format!(
            "Invalid filename '{}'. The 'rename' command only accepts a filename, not a path. Use 'mv' instead.",
            new_name
        ).into());
    }

    println!("Renaming (in-place) '{}' to '{}'...", old_name, new_name);

    // 3. 调用 `rename_file_inplace`
    match vault.rename_file_inplace(&file_entry.sha256sum, new_name) {
        Ok(_) => {
            println!("File successfully renamed.");
            Ok(())
        }
        Err(e) => {
            Err(format!("Error renaming file: {}", e).into())
        }
    }
}