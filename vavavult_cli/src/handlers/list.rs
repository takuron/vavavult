use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::{print_file_entries, print_list_result};

pub fn handle_list(vault: &Vault, path: Option<String>, search: Option<String>) -> Result<(), Box<dyn Error>> {
    match (path, search) {
        // 模式 1: list -s <keyword>
        (None, Some(keyword)) => {
            let files = vault.find_by_name_fuzzy(&keyword)?;
            println!("Found {} file(s) matching '{}':", files.len(), keyword);
            Ok(print_file_entries(&files))
        }
        // 模式 2: list -p <path>
        (Some(p), None) => {
            let result = vault.list_by_path(&p)?;
            println!("Contents of '{}':", p);
            Ok(print_list_result(&result))
        }
        // 模式 3: list (无参数)
        (None, None) => {
            let files = vault.list_all()?;
            println!("All {} file(s) in the vault:", files.len());
            Ok(print_file_entries(&files))
        }
        // clap 的 group 功能会阻止这种情况发生，但 match 需要它是详尽的
        (Some(_), Some(_)) => unreachable!(),
    }
}