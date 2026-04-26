use crate::errors::CliError;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryPathResult, Vault};

fn resolve_file_destination(
    source_path: &VaultPath,
    destination: &str,
) -> Result<VaultPath, CliError> {
    let dest_path = VaultPath::from(destination);
    if dest_path.is_dir() {
        let file_name = source_path.file_name().ok_or_else(|| {
            CliError::InvalidTarget(format!(
                "Source '{}' is not a file path and cannot be moved into a directory.",
                source_path
            ))
        })?;
        return Ok(dest_path.join(file_name)?);
    }
    Ok(dest_path)
}

/// 处理 'mv' (Move) 命令
pub fn handle_move(
    vault: &mut Vault,
    source_path: &str,
    destination: String,
) -> Result<(), CliError> {
    if !source_path.starts_with('/') {
        return Err(CliError::InvalidTarget(format!(
            "Move source '{}' is not a vault path. The mv command only accepts source paths starting with '/'.",
            source_path
        )));
    }

    let source_path = VaultPath::from(source_path);
    let dest_path = if source_path.is_file() {
        resolve_file_destination(&source_path, destination.as_str())?
    } else {
        VaultPath::from(destination.as_str())
    };

    if source_path.is_file() {
        // 文件移动、文件到目录移动、跨目录重命名和原地重命名都交给统一路径 API。
        match vault.find_by_path(&source_path)? {
            QueryPathResult::Found(_) => {}
            QueryPathResult::NotFound => {
                return Err(CliError::EntryNotFound(format!(
                    "File not found at path '{}'.",
                    source_path
                )));
            }
        };
        println!("Moving file '{}' to '{}'...", source_path, dest_path);
        vault.move_path(&source_path, &dest_path)?;
        println!("File successfully moved.");
        Ok(())
    } else {
        // 目录移动和目录原地重命名也交给统一路径 API。
        if dest_path.is_file() {
            return Err(CliError::InvalidTarget(
                "Cannot move a directory to a file path. Destination must be a directory."
                    .to_string(),
            ));
        }

        println!("Moving directory '{}' to '{}'...", source_path, dest_path);
        vault.move_path(&source_path, &dest_path)?;
        println!("Directory successfully moved.");
        Ok(())
    }
}
