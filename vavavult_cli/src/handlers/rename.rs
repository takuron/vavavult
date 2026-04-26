use crate::errors::CliError;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;

/// 处理文件或目录重命名命令
pub fn handle_file_rename(
    vault: &mut Vault,
    source_path: &str,
    new_name: &str,
) -> Result<(), CliError> {
    if !source_path.starts_with('/') {
        return Err(CliError::InvalidTarget(format!(
            "Rename source '{}' is not a vault path. The rename command only accepts source paths starting with '/'.",
            source_path
        )));
    }

    let source_path = VaultPath::from(source_path);

    println!("Renaming '{}' to '{}'...", source_path, new_name);
    vault.rename_path_inplace(&source_path, new_name)?;

    println!("Path successfully renamed.");
    Ok(())
}
