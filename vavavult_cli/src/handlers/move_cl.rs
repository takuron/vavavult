use crate::utils::{Target, get_all_files_recursively, identify_target};
use std::error::Error;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryResult, Vault};

/// 处理 'mv' (Move) 命令
pub fn handle_move(
    vault: &mut Vault,
    target: &str,
    destination: String,
) -> Result<(), Box<dyn Error>> {
    let source = identify_target(target)?;
    let dest_path = VaultPath::from(destination.as_str());

    match source {
        // --- 情况1：源是通过哈希值的单个文件 ---
        Target::Hash(hash) => {
            let file_entry = match vault.find_by_hash(&hash)? {
                QueryResult::Found(entry) => entry,
                QueryResult::NotFound => {
                    return Err(format!("File not found with hash '{}'.", hash).into());
                }
            };
            println!("Moving file '{}' to '{}'...", file_entry.path, dest_path);
            vault.move_file(&file_entry.sha256sum, &dest_path)?;
            println!("File successfully moved.");
        }

        // --- 情况2：源是文件路径 ---
        Target::Path(source_path) if source_path.is_file() => {
            let file_entry = match vault.find_by_path(&source_path)? {
                QueryResult::Found(entry) => entry,
                QueryResult::NotFound => {
                    return Err(format!("File not found at path '{}'.", source_path).into());
                }
            };
            println!("Moving file '{}' to '{}'...", source_path, dest_path);
            vault.move_file(&file_entry.sha256sum, &dest_path)?;
            println!("File successfully moved.");
        }

        // --- 情况3：源是目录路径 ---
        Target::Path(source_path) => {
            //因为上面的卫语句，这里一定是目录
            if dest_path.is_file() {
                return Err(
                    "Cannot move a directory to a file path. Destination must be a directory."
                        .into(),
                );
            }

            println!("Moving directory '{}' to '{}'...", source_path, dest_path);

            let files_to_move = get_all_files_recursively(vault, source_path.as_str())?;

            if files_to_move.is_empty() {
                println!(
                    "Source directory '{}' is empty or does not exist. Nothing to move.",
                    source_path
                );
                return Ok(());
            }

            let mut moved_count = 0;
            for file_entry in &files_to_move {
                let relative_path = file_entry
                    .path
                    .as_str()
                    .strip_prefix(source_path.as_str())
                    .ok_or_else(|| {
                        format!(
                            "Failed to create relative path for '{}' from base '{}'",
                            file_entry.path, source_path
                        )
                    })?;

                let new_path = dest_path.join(relative_path)?;

                vault.move_file(&file_entry.sha256sum, &new_path)?;
                moved_count += 1;
            }

            println!(
                "Successfully moved {} files from '{}'.",
                moved_count, source_path
            );
        }
    }

    Ok(())
}
