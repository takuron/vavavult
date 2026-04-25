use crate::core::helpers::{Target, identify_target};
use crate::errors::CliError;
use vavavult::vault::Vault;

/// 处理文件重命名命令
pub fn handle_file_rename(vault: &mut Vault, target: &str, new_name: &str) -> Result<(), CliError> {
    let source_path = match identify_target(target)? {
        Target::Path(path) => path,
        Target::Hash(_) => {
            return Err(CliError::InvalidTarget(
                "The rename command now only accepts a VaultPath source.".to_string(),
            ));
        }
    };

    // 构造同目录目标路径，让统一移动 API 处理文件或目录重命名。
    let parent_path = source_path.parent()?;
    let target_name = if source_path.is_dir() && !new_name.ends_with('/') {
        format!("{}/", new_name)
    } else {
        new_name.to_string()
    };
    let target_path = parent_path.join(&target_name)?;

    println!("Renaming '{}' to '{}'...", source_path, target_path);
    vault.move_path(&source_path, &target_path)?;

    println!("Path successfully renamed.");
    Ok(())
}
