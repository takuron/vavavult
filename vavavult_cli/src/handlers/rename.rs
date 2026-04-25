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

    println!("Renaming '{}' to '{}'...", source_path, new_name);
    vault.rename_path_inplace(&source_path, new_name)?;

    println!("Path successfully renamed.");
    Ok(())
}
