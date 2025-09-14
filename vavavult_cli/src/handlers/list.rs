use std::error::Error;
use vavavult::vault::Vault;
use crate::utils::{print_file_details, print_file_entries, print_list_result};

pub fn handle_list(
    vault: &Vault,
    path: Option<String>,
    search: Option<String>,
    tag: Option<String>, // <-- 新增参数
    detail: bool,
)  -> Result<(), Box<dyn Error>> {
    // 根据模式获取文件列表
    let files = match (path, search, tag) { // <-- 更新 match 表达式
        // 按名称搜索
        (None, Some(keyword), None) => {
            let found = vault.find_by_name_fuzzy(&keyword)?;
            println!("Found {} file(s) matching '{}':", found.len(), keyword);
            found
        }
        // 按路径列出
        (Some(p), None, None) => {
            let result = vault.list_by_path(&p)?;
            println!("Contents of '{}':", p);
            print_list_result(&result);
            return Ok(());
        }
        // --- 新增：按标签搜索 ---
        (None, None, Some(t)) => {
            let found = vault.find_by_tag(&t)?;
            println!("Found {} file(s) with tag '{}':", found.len(), &t);
            found
        }
        // 列出全部
        (None, None, None) => {
            let all_files = vault.list_all()?;
            println!("All {} file(s) in the vault:", all_files.len());
            all_files
        }
        _ => unreachable!(),
    };

    // 根据 `detail` 标志决定调用哪个打印函数
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