# vavavult

[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)](https://opensource.org/licenses/LGPL-2.1)
[![Build Status](https://github.com/takuron/vavavult/workflows/Rust/badge.svg)](https://github.com/takuron/vavavult/actions)

[English](./README.md) | [简体中文](./README_zh-CN.md)

A secure, robust, and concurrent local file vault library for Rust. Designed to manage, encrypt, and query collections of files with rich metadata and content deduplication.

> **Note:** This project is currently in active development (V2). It has not yet been published to crates.io.

## ✨ Features

- **🔒 Secure Encrypted Storage**: Optional end-to-end encryption for both the vault's database (using SQLCipher) and individual file content (using `AES-256-GCM` stream cipher with `PBKDF2` key derivation).
- **🗂️ Content-Addressable Storage**: Files are stored and addressed based on their `SHA256` hash, automatically deduplicating content and ensuring data integrity.
- **🧩 Modular Storage Backend**: Decoupled architecture supporting custom storage backends. Comes with a default robust **Local Filesystem** backend with atomic write support.
- **🏷️ Rich Metadata & Tags**: Organize your files with flexible tags and custom key-value metadata pairs.
- **⚡ High Performance & Concurrency**:
  - Thread-safe design enabling parallel file encryption and decryption.
  - Stream-based processing for low memory footprint, even with large files.
- **🔍 Powerful Querying**:
  - Find files by exact path, hash, tag, or fuzzy keyword search.
  - List files and directories in a hierarchical structure.
- **📦 Transactional Consistency**: All metadata is managed in a `SQLite` database, guaranteeing atomic operations and consistency between metadata and physical data.

## 🚀 Getting Started

Since `vavavult` is not yet on crates.io, you can add it as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
vavavult = { git = "https://github.com/takuron/vavavult.git", branch = "main" }
```

Or, if you have cloned the repository locally:

```toml
[dependencies]
vavavult = { path = "path/to/vavavult" }
```

## 💡 Usage Example

Here's a quick example of the vault's lifecycle: creating a vault, adding a file using `VaultPath`, querying, and extracting it.

```rust
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use vavavult::vault::{QueryResult, Vault};
use vavavult::file::VaultPath;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set up paths for the vault and a dummy file
    let temp_dir = tempdir()?;
    let vault_root = temp_dir.path().join("my_vault");
    let source_file_path = temp_dir.path().join("my_secret.txt");
    fs::write(&source_file_path, "This is top secret data!")?;

    // 2. Create a new, encrypted vault using the default local storage backend
    //    Use `Vault::create_vault` if you want to inject a custom backend.
    println!("Creating encrypted vault...");
    let mut vault = Vault::create_vault_local(
        &vault_root,
        "my-secure-vault",
        Some("strongpassword123")
    )?;

    // 3. Add the file to the vault
    //    We use `VaultPath` to define the internal path structure.
    println!("Adding file...");
    let internal_path = VaultPath::from("/documents/secret.txt");
    let file_hash = vault.add_file(&source_file_path, &internal_path)?;
    println!("File added with hash: {}", file_hash);

    // 4. Query the file by its internal path
    println!("Querying file...");
    if let QueryResult::Found(entry) = vault.find_by_path(&internal_path)? {
        println!("Found file: {}", entry.path);
        println!("Encrypted Hash: {}", entry.sha256sum);

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

## 🛠️ Advanced Usage: Parallel Processing

For high-throughput scenarios (e.g., adding or extracting thousands of files), `vavavult` exposes standalone functions that allow you to perform expensive encryption/decryption operations in parallel (e.g., using `rayon`) without locking the main database.

- `prepare_addition_task_standalone`: Encrypts data to a staging area.
- `execute_extraction_task_standalone`: Decrypts data from storage.

See the documentation or `vavavult_cli` implementation for details on how to implement parallel workflows.


## 📜 License

This project is licensed under the **GNU Lesser General Public License v2.1** ([LGPL-2.1](https://opensource.org/licenses/LGPL-2.1)). See the [LICENSE](LICENSE) file for details.