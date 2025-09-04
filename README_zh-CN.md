# vavavult

[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)](https://opensource.org/licenses/LGPL-2.1)
[![Build Status](https://github.com/takuron/vavavult/workflows/Rust/badge.svg)](https://github.com/takuron/vavavult/actions)

[English](./README.md) | [简体中文](./README_zh-CN.md)

一个安全、健壮的 Rust 本地文件保险库，旨在通过丰富的元数据来管理、加密和查询文件集合。

## ✨ 功能特性

* **🔒 安全加密存储**: 可选的端到端加密，使用 `AES-256-GCM` 算法保护保险库的数据库和单个文件，密钥通过 `PBKDF2` 派生。
* **🗂️ 内容寻址存储**: 文件基于其 `SHA256` 哈希值进行存储，自动实现内容去重并确保数据完整性。
* **🏷️ 丰富的元数据**: 使用灵活的标签和键值对 (key-value) 元数据来组织你的文件。
* **🔍 强大的查询能力**:
    * 按名称、哈希或标签查找文件。
    * 对文件名进行模糊搜索。
    * 组合名称和标签进行查询。
    * 以层级结构列出文件和目录。
* **📦 事务性数据库**: 所有元数据都在 `SQLite` 数据库 (支持 SQLCipher) 中管理，保证了操作的原子性。
* **🦀 简洁现代的 API**: 提供一个清晰、符合人体工程学的 Rust API，可以轻松集成到任何应用程序中。

## 🚀 快速开始

要开始使用 `vavavult`，请在你的 `Cargo.toml` 文件中添加以下依赖：

```toml
[dependencies]
vavavult = "0.1.0" # 或 crates.io 上的最新版本
```

## 💡 用法示例

这是一个展示保险库核心生命周期的简短示例：创建、添加、查询和提取。

```rust
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vavavult::vault::{QueryResult, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 设置保险库和一个虚拟文件的路径
    let temp_dir = tempdir()?;
    let vault_path = temp_dir.path().join("my_vault");
    let source_file_path = temp_dir.path().join("my_secret.txt");
    fs::write(&source_file_path, "这是绝密数据！")?;

    // 2. 创建一个新的加密保险库
    println!("正在创建加密保险库...");
    let vault = Vault::create_vault(&vault_path, "my-secure-vault", Some("strongpassword123"))?;

    // 3. 将文件添加到保险库
    println!("正在添加文件...");
    let file_hash = vault.add_file(&source_file_path, Some("/documents/secret.txt"))?;
    println!("文件已添加，哈希值为: {}", file_hash);

    // 4. 按名称查询文件
    println!("正在查询文件...");
    if let QueryResult::Found(entry) = vault.find_by_name("/documents/secret.txt")? {
        println!("找到文件: {}", entry.name);

        // 5. 将文件提取回文件系统
        println!("正在提取文件...");
        let extract_path = temp_dir.path().join("extracted_secret.txt");
        vault.extract_file(&entry.sha256sum, &extract_path)?;
        
        let content = fs::read_to_string(&extract_path)?;
        println!("文件已提取。内容: '{}'", content);
        assert_eq!(content, "这是绝密数据！");
    }

    Ok(())
}
```

## 📜 开源许可

本项目采用 **GNU 宽通用公共许可证 v2.1** ([LGPL-2.1](https://opensource.org/licenses/LGPL-2.1))。详情请参阅 [LICENSE](LICENSE) 文件。