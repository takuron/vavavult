use crate::errors::CliError;
use crate::ui::printer::print_list_result;
use vavavult::file::VaultPath;
use vavavult::vault::{FilePathEntry, ListPathEntry, Vault};

// This enum is an internal detail of the list handler module.
pub enum ListResult {
    Shallow(Vec<ListPathEntry>),
    Recursive(Vec<FilePathEntry>),
}

/// Handles the 'ls' command and prints the results directly.
pub fn handle_list(
    vault: &Vault,
    path: Option<String>,
    long: bool,
    recursive: bool,
) -> Result<(), CliError> {
    let target_path_str = path.unwrap_or_else(|| "/".to_string());
    let target_vault_path = VaultPath::from(target_path_str.as_str());

    if target_vault_path.is_file() {
        return Err(CliError::InvalidTarget(format!(
            "Cannot list '{}': Path is a file, not a directory. 'ls' is for directories.",
            target_vault_path
        )));
    }

    // 1. Get data
    let list_result = if recursive {
        let all_files = vault.list_all_recursive(&target_vault_path)?;
        ListResult::Recursive(all_files)
    } else {
        let entries = vault.list_by_path(&target_vault_path)?;
        ListResult::Shallow(entries)
    };

    // 2. Get display options
    let colors_enabled = vault.is_feature_enabled("colorfulTag").unwrap_or(false);

    // 3. Pass to printer
    print_list_result(
        vault,
        &list_result,
        long,
        colors_enabled,
        &target_vault_path,
    );

    Ok(())
}
