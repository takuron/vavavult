// [vavavult_cli/src/handlers/list.rs]

use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::{print_file_details, print_file_entries, print_list_result};

pub fn handle_list(
    vault: &Vault,
    path: Option<String>,
    search: Option<String>,
    detail: bool,
) -> Result<(), Box<dyn Error>> {
    // 根据模式获取文件列表
    let files = match (path, search) {
        // 按名称和标签模糊搜索
        (None, Some(keyword)) => {
            // [修改] 调用新的统一搜索函数
            let found = vault.find_by_name_or_tag_fuzzy(&keyword)?;
            println!(
                "Found {} file(s) matching '{}' (in name or tags):",
                found.len(),
                keyword
            );
            found
        }
        // 按路径列出
        (Some(p), None) => {
            let result = vault.list_by_path(&p)?;
            println!("Contents of '{}':", p);
            print_list_result(&result);
            return Ok(());
        }

        // 列出全部
        (None, None) => {
            let all_files = vault.list_all()?;
            println!("All {} file(s) in the vault:", all_files.len());
            all_files
        }
        _ => unreachable!(), // (Some, Some) 组合被 clap 的 "list_mode" group 阻止
    };

    // 根据 `detail` 标志决定调用哪个打印函数 (此部分逻辑不变)
    if detail {
        for file in &files {
            print_file_details(file);
        }
        if !files.is_empty() {
            println!("----------------------------------------");
        }
    } else {
        print_file_entries(&files);
    }

    Ok(())
}