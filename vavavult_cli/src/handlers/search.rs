use crate::errors::CliError;
use crate::ui::printer::{print_file_details, print_recursive_file_item};
use vavavult::vault::Vault;

/// Handles the 'search' command and prints the results directly.
pub fn handle_search(vault: &Vault, keyword: &str, long: bool) -> Result<(), CliError> {
    let found_files = vault.find_by_keyword(keyword)?;

    if found_files.is_empty() {
        println!("No files found matching '{}' (in name or tags).", keyword);
    } else {
        println!(
            "Found {} file(s) matching '{}' (in name or tags):",
            found_files.len(),
            keyword
        );

        let colors_enabled = vault.is_feature_enabled("colorfulTag").unwrap_or(false);

        if long {
            for file in &found_files {
                print_file_details(file, colors_enabled);
            }
            if !found_files.is_empty() {
                println!("----------------------------------------");
            }
        } else {
            for file in &found_files {
                print_recursive_file_item(file, colors_enabled);
            }
        }
    }
    Ok(())
}
