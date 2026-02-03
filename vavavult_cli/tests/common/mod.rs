//!
//! # Test Common Utilities
//!
//! This module provides common utilities for writing integration tests for the `vavavult_cli`.
//! It is designed to abstract away the boilerplate of setting up test environments,
//! running CLI commands, and handling interactive prompts.
//!
//
// // # 测试通用工具
// //
// // 该模块为 `vavavult_cli` 的集成测试提供通用工具。
// // 旨在抽象化设置测试环境、运行 CLI 命令以及处理交互式提示的样板代码。
// //

use assert_cmd::Command;
use predicates::prelude::predicate;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::{TempDir, tempdir};

/// Represents the context for a single test, including a temporary directory.
///
/// This struct ensures that each test runs in an isolated environment, preventing
/// interference between tests.
/// The temporary directory is automatically cleaned up
/// when the `TestContext` goes out of scope.
///
/// # Fields
/// * `temp_dir` - A handle to the temporary directory.
/// * `vault_path` - The path to the vault created within the temporary directory.
pub struct TestContext {
    /// A handle to the temporary directory. Held for its Drop behavior to ensure cleanup.
    pub _temp_dir: TempDir,
    /// The path to the vault created within the temporary directory.
    pub vault_path: PathBuf,
}

impl TestContext {
    /// Creates a new vault for testing purposes.
    pub fn new(vault_name: &str, password: &str) -> anyhow::Result<Self> {
        let temp_dir = tempdir()?;
        let vault_path = temp_dir.path().join(vault_name);

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
        cmd.arg("create").arg(temp_dir.path());

        let use_encryption = !password.is_empty();
        let input = if use_encryption {
            format!("{}\ny\n{}\n{}\n", vault_name, password, password)
        } else {
            format!("{}\nn\n", vault_name)
        };

        cmd.write_stdin(input).assert().success();

        Ok(TestContext {
            _temp_dir: temp_dir,
            vault_path,
        })
    }

    /// Helper to add a file to the vault for testing.
    pub fn add_file(
        &self,
        file_name: &str,
        content: &str,
        vault_path: Option<&str>,
    ) -> anyhow::Result<()> {
        let temp_file_path = self._temp_dir.path().join(file_name);
        fs::write(&temp_file_path, content)?;

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
        cmd.arg("open").arg(&self.vault_path);

        let mut repl_command = format!("add \"{}\"", temp_file_path.to_str().unwrap());
        if let Some(p) = vault_path {
            repl_command.push_str(&format!(" -p {}", p));
        }
        let repl_input = format!("{}\nexit\n", repl_command);

        cmd.write_stdin(repl_input)
            .assert()
            .success()
            .stdout(predicate::str::contains("Successfully added file"));

        Ok(())
    }

    /// Helper to get a file's hash and path by running `ls -l`.
    /// Helper to get a file's hash and path by running `ls -l` on its parent directory.
    pub fn get_file_hash_and_path(&self, vault_path: &str) -> anyhow::Result<(String, String)> {
        // `ls` works on directories, so we list the parent and find the file.
        let vault_path_p = Path::new(vault_path);
        let parent_dir = vault_path_p
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("/");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
        cmd.arg("open").arg(&self.vault_path);

        let repl_input = format!("ls -l {}\nexit\n", parent_dir);

        let output = cmd.write_stdin(repl_input).output()?;
        let stdout = String::from_utf8(output.stdout)?;

        // Split output into blocks separated by '----'
        let blocks = stdout.split("----------------------------------------");

        for block in blocks {
            let path_line_match = format!("Path:            {}", vault_path);
            if block.contains(&path_line_match) {
                // This is the correct block for our file.
                let hash_line = block
                    .lines()
                    .find(|line| line.trim().starts_with("SHA256 (ID):"))
                    .ok_or_else(|| {
                        anyhow::anyhow!("Could not find hash in file block for {}", vault_path)
                    })?;
                let hash = hash_line.split(':').nth(1).unwrap().trim().to_string();

                let path = vault_path.to_string(); // We already know the path we are looking for

                return Ok((hash, path));
            }
        }

        Err(anyhow::anyhow!(
            "Could not find file entry for '{}' in `ls -l {}` output. STDOUT:\n{}",
            vault_path,
            parent_dir,
            stdout
        ))
    }

    /// Helper to construct the physical path of a data file from its hash.
    pub fn get_physical_file_path(&self, hash: &str) -> PathBuf {
        self.vault_path.join("data").join(hash)
    }

    /// Returns the path to the temporary directory.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        self._temp_dir.path()
    }
}
