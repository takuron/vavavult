use crate::errors::CliError;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;

fn resolve_file_destination(
    source_path: &VaultPath,
    destination: &str,
) -> Result<VaultPath, CliError> {
    let dest_path = VaultPath::from(destination);
    if dest_path.is_dir() {
        let file_name = source_path.file_name().ok_or_else(|| {
            CliError::InvalidTarget(format!(
                "Source '{}' is not a file path and cannot be copied into a directory.",
                source_path
            ))
        })?;
        return Ok(dest_path.join(file_name)?);
    }
    Ok(dest_path)
}

/// 处理 'copy'/'cp' 命令
pub fn handle_copy(
    vault: &mut Vault,
    source_path: &str,
    destination: String,
) -> Result<(), CliError> {
    if !source_path.starts_with('/') {
        return Err(CliError::InvalidTarget(format!(
            "Copy source '{}' is not a vault path. The copy command only accepts source paths starting with '/'.",
            source_path
        )));
    }

    let source_path = VaultPath::from(source_path);
    let dest_path = resolve_file_destination(&source_path, destination.as_str())?;

    println!("Copying file '{}' to '{}'...", source_path, dest_path);
    vault.copy_file_path(&source_path, &dest_path)?;
    println!("File successfully copied.");
    Ok(())
}
