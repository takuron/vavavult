# vavavult

[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)](https://opensource.org/licenses/LGPL-2.1)
[![Build Status](https://github.com/takuron/vavavult/workflows/Rust/badge.svg)](https://github.com/takuron/vavavult/actions)

[English](./README.md) | [简体中文](./README_zh-CN.md)

A secure and robust local file vault library for Rust, designed to manage, encrypt, and query collections of files with rich metadata.

## ✨ Features

* **🔒 Secure Encrypted Storage**: Optional end-to-end encryption for both the vault's database and individual files using `AES-256-GCM` with keys derived via `PBKDF2`.
* **🗂️ Content-Addressable Storage**: Files are stored based on their `SHA256` hash, automatically deduplicating content and ensuring data integrity.
* **🏷️ Rich Metadata**: Organize your files with flexible tags and key-value metadata.
* **🔍 Powerful Querying**:
    * Find files by name, hash, or tag.
    * Perform fuzzy-searches on file names.
    * Combine name and tag queries.
    * List files and directories in a hierarchical structure.
* **📦 Transactional Database**: All metadata is managed in a `SQLite` database (with SQLCipher support), guaranteeing atomic operations.
* **🦀 Simple & Modern API**: A clean, ergonomic Rust API that is easy to integrate into any application.

## 🚀 Getting Started

To start using `vavavult`, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
vavavult = "0.1.0" # Or the latest version on crates.io
```

## 💡 Usage Example

Here's a quick example of the vault's lifecycle: create, add, query, and extract.

```rust
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vavavult::vault::{QueryResult, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set up paths for the vault and a dummy file
    let temp_dir = tempdir()?;
    let vault_path = temp_dir.path().join("my_vault");
    let source_file_path = temp_dir.path().join("my_secret.txt");
    fs::write(&source_file_path, "This is top secret data!")?;

    // 2. Create a new, encrypted vault
    println!("Creating encrypted vault...");
    let vault = Vault::create_vault(&vault_path, "my-secure-vault", Some("strongpassword123"))?;

    // 3. Add the file to the vault
    println!("Adding file...");
    let file_hash = vault.add_file(&source_file_path, Some("/documents/secret.txt"))?;
    println!("File added with hash: {}", file_hash);

    // 4. Query the file by its name
    println!("Querying file...");
    if let QueryResult::Found(entry) = vault.find_by_name("/documents/secret.txt")? {
        println!("Found file: {}", entry.name);

        // 5. Extract the file back to the filesystem
        println!("Extracting file...");
        let extract_path = temp_dir.path().join("extracted_secret.txt");
        vault.extract_file(&entry.sha256sum, &extract_path)?;
        
        let content = fs::read_to_string(&extract_path)?;
        println!("File extracted. Content: '{}'", content);
        assert_eq!(content, "This is top secret data!");
    }

    Ok(())
}
```

## 📜 License

This project is licensed under the **GNU Lesser General Public License v2.1** ([LGPL-2.1](https://opensource.org/licenses/LGPL-2.1)). See the [LICENSE](LICENSE) file for details.