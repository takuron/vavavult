use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use vavavult::vault::{QueryResult, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 为我们的保险库创建一个临时目录。
    let dir = tempdir()?;
    let vault_path = dir.path();
    println!("临时保险库将创建于: {:?}", vault_path);

    // --- 创建一个新保险库 ---
    println!("\n正在创建一个名为 'my-first-vault' 的新保险库...");
    let mut vault = Vault::create_vault(vault_path, "my-first-vault", None)?;
    println!("保险库创建成功!");
    assert_eq!(vault.config.name, "my-first-vault");

    // --- 向保险库中添加一个文件 ---
    println!("\n正在向保险库添加新文件 'hello.txt'...");
    let source_file_path = dir.path().join("hello.txt");
    let mut file = File::create(&source_file_path)?;
    file.write_all("来自 vavavult 示例的问候!".as_ref())?;

    let file_hash = vault.add_file(&source_file_path, Some("docs/greeting/hello.txt"))?;
    println!("文件添加成功! SHA256 哈希值: {}", file_hash);

    // --- 通过哈希值查询文件 ---
    println!("\n正在通过哈希值查询文件...");
    match vault.find_by_hash(&file_hash)? {
        QueryResult::Found(entry) => {
            println!("已通过哈希值找到文件!");
            println!("  - 在保险库中的名称: {}", entry.path);
            println!("  - SHA256: {}", entry.sha256sum);
        }
        QueryResult::NotFound => {
            panic!("文件应该能被找到!");
        }
    }

    // --- 通过名称查询文件 ---
    println!("\n正在通过名称查询文件...");
    let file_name_in_vault = "/docs/greeting/hello.txt";
    match vault.find_by_name(file_name_in_vault)? {
        QueryResult::Found(entry) => {
            println!("已通过名称 '{}' 找到文件!", entry.path);
        }
        QueryResult::NotFound => {
            panic!("文件应该能通过名称被找到!");
        }
    }

    // 丢弃 vault 实例以模拟关闭应用程序
    drop(vault);

    // --- 重新打开已存在的保险库 ---
    println!("\n正在重新打开已存在的保险库...");
    let reopened_vault = Vault::open_vault(vault_path, None)?;
    println!("保险库重新打开成功。保险库名称: {}", reopened_vault.config.name);

    // 验证文件在重新打开的保险库中仍然存在
    let result = reopened_vault.find_by_hash(&file_hash)?;
    assert!(matches!(result, QueryResult::Found(_)));
    println!("已验证文件在重新打开的保险库中仍然存在。");

    println!("\n示例成功运行完毕!");
    Ok(())
}