use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vavavult::common::metadata::MetadataEntry;
use vavavult::vault::{Vault};

fn create_dummy_file(dir: &Path, name: &str, content: &[u8]) -> std::io::Result<()> {
    fs::write(dir.join(name), content)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 为我们的保险库创建一个临时目录。
    let dir = tempdir()?;
    let vault_path = dir.path();
    let password = "a_very_secret_password";

    // --- 创建一个新的加密保险库 ---
    println!("正在创建一个新的加密保险库...");
    let mut vault = Vault::create_vault(vault_path, "secure-vault", Some(password))?;
    println!("加密保险库创建成功!");

    // --- 添加多个带标签和元数据的文件 ---
    println!("\n正在添加带有标签和元数据的文件...");
    create_dummy_file(dir.path(), "report.txt", "这是年度报告。".as_ref())?;
    create_dummy_file(dir.path(), "logo.png", "伪PNG数据".as_ref())?;

    let report_hash = vault.add_file(&dir.path().join("report.txt"), Some("work/2025/annual_report.txt"))?;
    let logo_hash = vault.add_file(&dir.path().join("logo.png"), Some("assets/logo.png"))?;

    // 添加标签
    vault.add_tags(&report_hash, &["work", "finance", "report"])?;
    vault.add_tag(&logo_hash, "asset")?;
    println!("标签已添加。");

    // 设置元数据
    vault.set_file_metadata(&report_hash, MetadataEntry {
        key: "author".to_string(),
        value: "张三".to_string(),
    })?;
    vault.set_file_metadata(&report_hash, MetadataEntry {
        key: "status".to_string(),
        value: "final".to_string(),
    })?;
    println!("元数据已设置。");

    // --- 执行高级查询 ---
    println!("\n正在执行高级搜索...");
    let finance_files = vault.find_by_tag("finance")?;
    assert_eq!(finance_files.len(), 1);
    println!("找到 {} 个带有 'finance' 标签的文件。", finance_files.len());

    let report_files = vault.find_by_name_fuzzy("report")?;
    assert_eq!(report_files.len(), 1);
    println!("找到 {} 个名称中包含 'report' 的文件。", report_files.len());

    // --- 提取文件 ---
    println!("\n正在提取文件 '{}'...", report_hash);
    let extract_path = dir.path().join("extracted_report.txt");
    vault.extract_file(&report_hash, &extract_path)?;

    let content = fs::read_to_string(&extract_path)?;
    assert_eq!(content, "这是年度报告。");
    println!("文件已成功提取至: {:?}", extract_path);
    println!("  - 提取出的内容: '{}'", content);

    drop(vault);

    // --- 使用正确密码重新打开加密保险库 ---
    println!("\n正在使用正确密码重新打开加密保险库...");
    let reopened_vault = Vault::open_vault(vault_path, Some(password))?;
    assert_eq!(reopened_vault.config.name, "secure-vault");
    println!("成功重新打开加密保险库!");

    // --- 尝试使用错误密码打开 (应该会失败) ---
    println!("\n正在尝试使用错误密码重新打开...");
    let result = Vault::open_vault(vault_path, Some("wrong_password"));
    assert!(result.is_err());
    println!("与预期一致，使用错误密码打开失败了。");

    println!("\n高级示例成功运行完毕!");
    Ok(())
}