use std::error::Error;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use vavavult::file::FileEntry;
use vavavult::vault::{ListResult, QueryResult, Vault};

/// 打印 `FileEntry` 列表的辅助函数
pub fn print_file_entries(files: &[FileEntry]) {
    if files.is_empty() {
        return;
    }
    // 调整列的顺序和宽度
    println!("{:<60} {:<30} {}", "Name", "Tags", "SHA256 (short)");
    println!("{}", "-".repeat(120));
    for entry in files {
        let short_hash = &entry.sha256sum[..12];
        let tags = if entry.tags.is_empty() {
            "-".to_string()
        } else {
            entry.tags.join(", ")
        };
        // 调整变量的打印顺序
        println!("{:<60} {:<30} {}", entry.name, tags, short_hash);
    }
}


// --- 新增: 辅助函数 ---

/// 根据 name 或 sha256 查找文件，返回找到的 FileEntry
pub fn find_file_entry(vault: &Vault, name: Option<String>, sha: Option<String>) -> Result<FileEntry, Box<dyn Error>> {
    let query_result = if let Some(n) = name {
        vault.find_by_name(&n)?
    } else if let Some(s) = sha {
        vault.find_by_hash(&s)?
    } else {
        unreachable!(); // Clap 应该已经阻止了这种情况
    };

    match query_result {
        QueryResult::Found(entry) => Ok(entry),
        QueryResult::NotFound => Err("File not found in the vault.".into()),
    }
}

/// 确定最终的输出路径
pub fn determine_output_path(entry: &FileEntry, dest_dir: PathBuf, output_name: Option<String>) -> PathBuf {
    let final_filename = output_name.unwrap_or_else(|| {
        Path::new(&entry.name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed_file")
            .to_string()
    });
    dest_dir.join(final_filename)
}

/// 向用户请求确认破坏性操作
pub fn confirm_action(prompt: &str) -> Result<bool, io::Error> {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    Ok(confirmation.trim().eq_ignore_ascii_case("y") || confirmation.trim().eq_ignore_ascii_case("yes"))
}

/// 打印 `ListResult` 的辅助函数
pub fn print_list_result(result: &ListResult) {
    if result.subdirectories.is_empty() && result.files.is_empty() {
        println!("(empty)");
        return;
    }
    // 先打印目录
    for dir in &result.subdirectories {
        println!("[{}/]", dir);
    }
    // 再打印文件
    print_file_entries(&result.files);
}