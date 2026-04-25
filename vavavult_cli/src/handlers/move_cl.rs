use crate::core::helpers::{Target, identify_target};
use crate::errors::CliError;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryPathResult, Vault};

/// 处理 'mv' (Move) 命令
pub fn handle_move(vault: &mut Vault, target: &str, destination: String) -> Result<(), CliError> {
    let source = identify_target(target)?;
    let dest_path = VaultPath::from(destination.as_str());

    match source {
        // 移动 API 只接受保险库路径，不再接受哈希。
        Target::Hash(_) => Err(CliError::InvalidTarget(
            "The mv command now only accepts a VaultPath source.".to_string(),
        )),

        // 文件移动、跨目录重命名和原地重命名都交给统一路径 API。
        Target::Path(source_path) if source_path.is_file() => {
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
        }

        // 目录移动和目录原地重命名也交给统一路径 API。
        Target::Path(source_path) => {
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
}
