# vavavult

[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)](https://opensource.org/licenses/LGPL-2.1)
[![Build Status](https://github.com/takuron/vavavult/workflows/Rust/badge.svg)](https://github.com/takuron/vavavult/actions)

[English](./README.md) | [简体中文](./README_zh-CN.md)

一个安全、健壮且支持并发的 Rust 本地文件保险库库。旨在通过丰富的元数据和内容去重机制来管理、加密和查询文件集合。

> **注意：** 本项目目前处于活跃开发阶段 (V2)。尚未发布到 crates.io。

## ✨ 功能特性

* **🔒 安全加密存储**: 可选的端到端加密，同时保护保险库数据库 (使用 SQLCipher) 和单个文件内容 (使用 `AES-256-GCM` 流加密与 `PBKDF2` 密钥派生)。
* **🗂️ 内容寻址存储**: 文件基于其 `SHA256` 哈希值进行存储和寻址，自动实现内容去重并确数据完整性。
* **🧩 模块化存储后端**: 解耦架构，支持自定义存储后端。默认提供健壮的且支持原子写入的 **本地文件系统 (Local Filesystem)** 后端。
* **🏷️ 丰富的元数据与标签**: 使用灵活的标签和自定义键值对元数据来组织你的文件。
* **⚡ 高性能与并发**:
  * 线程安全设计，支持并行文件加密和解密。
  * 基于流的处理方式，即使处理大文件也能保持低内存占用。
* **🔍 强大的查询能力**:
  * 按精确路径、哈希、标签或模糊关键字查找文件。
  * 以层级结构列出文件和目录。
* **📦 事务一致性**: 所有元数据都在 `SQLite` 数据库中管理，保证了操作的原子性以及元数据与物理数据之间的一致性。

## 🚀 快速开始

### Windows 环境配置

编译此项目需要 OpenSSL 和 Perl：

1. **安装 vcpkg**：
   ```bash
   scoop install vcpkg
   ```

2. **安装 OpenSSL**：
   ```bash
   vcpkg install openssl:x64-windows
   ```

3. **安装 Perl**：
   ```bash
   scoop install strawberryperl
   ```

4. **安装 Perl 模块**：
   ```bash
   perl -MCPAN -e "install Locale::Maketext::Simple"
   ```

5. **配置环境变量**：
   ```
   OPENSSL_DIR=C:\Users\<你的用户名>\scoop\apps\vcpkg\current\installed\x64-windows
   OPENSSL_NO_VENDOR=1
   ```
   添加 Perl 到 PATH：`C:\Strawberry\perl\bin`

### 添加依赖

由于 `vavavult` 尚未发布到 crates.io，您需要在 `Cargo.toml` 中将其添加为 git 依赖项：

```toml
[dependencies]
vavavult = { git = "[https://github.com/takuron/vavavult.git](https://github.com/takuron/vavavult.git)", branch = "main" }
```

或者，如果您已将代码库克隆到本地：

```toml
[dependencies]
vavavult = { path = "path/to/vavavult" }
```

## 💡 用法示例

这是一个展示保险库核心生命周期的简短示例：创建保险库、使用 VaultPath 添加文件、查询和提取文件。

```rust
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vavavult::vault::{QueryResult, Vault};
use vavavult::file::VaultPath;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // 1. 设置保险库和一个虚拟文件的路径
  let temp_dir = tempdir()?;
  let vault_root = temp_dir.path().join("my_vault");
  let source_file_path = temp_dir.path().join("my_secret.txt");
  fs::write(&source_file_path, "这是绝密数据！")?;

  // 2. 使用默认的本地存储后端创建一个新的加密保险库
  //    如果你想注入自定义后端，请使用 `Vault::create_vault`。
  println!("正在创建加密保险库...");
  let mut vault = Vault::create_vault_local(
    &vault_root,
    "my-secure-vault",
    Some("strongpassword123")
  )?;

  // 3. 将文件添加到保险库
  //    我们使用 `VaultPath` 来定义保险库内部的路径结构。
  println!("正在添加文件...");
  let internal_path = VaultPath::from("/documents/secret.txt");
  let file_hash = vault.add_file(&source_file_path, &internal_path)?;
  println!("文件已添加，哈希值为: {}", file_hash);

  // 4. 通过内部路径查询文件
  println!("正在查询文件...");
  if let QueryResult::Found(entry) = vault.find_by_path(&internal_path)? {
    println!("找到文件: {}", entry.path);
    println!("加密哈希 (ID): {}", entry.sha256sum);

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

## 🛠️ 高级用法：并行处理

对于高吞吐量场景（例如添加或提取数千个文件），vavavult 暴露了独立函数 (standalone functions)，允许你在不锁定主数据库的情况下并行执行昂贵的加密/解密操作（例如配合 rayon 使用）。

- `prepare_addition_task_standalone`: 将数据加密到暂存区。
- `execute_extraction_task_standalone`: 从存储中解密数据。

有关如何实现并行工作流的详细信息，请参阅文档或 vavavult_cli 中的实现。

## 📜 开源许可

本项目采用 **GNU 宽通用公共许可证 v2.1** ([LGPL-2.1](https://opensource.org/licenses/LGPL-2.1))。详情请参阅 [LICENSE](LICENSE) 文件。