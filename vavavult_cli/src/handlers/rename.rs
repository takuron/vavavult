use crate::core::helpers::{
    Target, display_path_for_entry, find_file_entry, first_path_for_entry, identify_target,
};
use crate::errors::CliError;
use vavavult::vault::Vault;

/// 处理文件重命名命令
pub fn handle_file_rename(vault: &mut Vault, target: &str, new_name: &str) -> Result<(), CliError> {
    // 1. 查找要重命名的文件
    let file_entry = find_file_entry(vault, target)?;
    let old_name = display_path_for_entry(vault, &file_entry);
    let source_path = match identify_target(target)? {
        Target::Path(path) => path,
        Target::Hash(_) => first_path_for_entry(vault, &file_entry)?,
    };

    // 2. 验证 new_name 是纯文件名
    if new_name.contains('/') || new_name.contains('\\') {
        return Err(CliError::InvalidName(format!(
            "Invalid filename '{}'. The 'rename' command only accepts a filename, not a path. Use 'mv' instead.",
            new_name
        )));
    }

    println!("Renaming (in-place) '{}' to '{}'...", old_name, new_name);

    // 3. 调用路径级 rename，确保多路径映射只修改目标 dentry。
    vault.rename_file_inplace_by_path(&source_path, new_name)?;

    println!("File successfully renamed.");
    Ok(())
}

