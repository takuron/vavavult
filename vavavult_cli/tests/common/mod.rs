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
use std::path::{Path, PathBuf};
use tempfile::{TempDir, tempdir};

/// Represents the context for a single test, including a temporary directory.
///
/// This struct ensures that each test runs in an isolated environment, preventing
/// interference between tests. The temporary directory is automatically cleaned up
/// when the `TestContext` goes out of scope.
///
/// # Fields
/// * `temp_dir` - A handle to the temporary directory.
/// * `vault_path` - The path to the vault created within the temporary directory.
//
// // 代表单个测试的上下文，包含一个临时目录。
// //
// // 此结构确保每个测试都在隔离的环境中运行，防止测试之间的干扰。
// // 当 `TestContext` 离开作用域时，临时目录会自动被清理。
// //
// // # 字段
// // * `temp_dir` - 临时目录的句柄。
// // * `vault_path` - 在临时目录中创建的保险库的路径。
pub struct TestContext {
    /// A handle to the temporary directory. Held for its Drop behavior to ensure cleanup.
    // // 临时目录的句柄。持有它是为了利用其 Drop 行为来确保自动清理。
    pub _temp_dir: TempDir,
    /// The path to the vault created within the temporary directory.
    // // 在临时目录中创建的保险库的路径。
    pub vault_path: PathBuf,
}

impl TestContext {
    /// Creates a new vault for testing purposes.
    ///
    /// This function creates a new temporary directory and then invokes the `vavavult_cli create`
    /// command to initialize a new vault inside it. It handles the interactive prompts
    //  for vault name and password.
    ///
    /// # Arguments
    /// * `vault_name` - The name for the new vault.
    /// * `password` - The password for the new vault. An empty string means no encryption.
    ///
    /// # Returns
    /// A `Result` containing the `TestContext` on success.
    //
    // // 创建一个用于测试的新保险库。
    // //
    // // 此函数会创建一个新的临时目录，然后调用 `vavavult_cli create` 命令
    // // 在其中初始化一个新的保险库。它会自动处理保险库名称和密码的交互式提示。
    // //
    // // # 参数
    // // * `vault_name` - 新保险库的名称。
    // // * `password` - 新保险库的密码。空字符串表示不加密。
    // //
    // // # 返回
    // // 成功时返回包含 `TestContext` 的 `Result`。
    pub fn new(vault_name: &str, password: &str) -> anyhow::Result<Self> {
        // 1. 创建一个临时目录用于测试隔离
        let temp_dir = tempdir()?;
        let vault_path = temp_dir.path().join(vault_name);

        // 2. 准备创建保险库的命令
        //    create 命令接收的是父目录，然后在其中根据用户输入创建保险库目录
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
        cmd.arg("create").arg(temp_dir.path());

        // 3. 准备交互式输入：首先是保险库名称，然后是加密选项
        let use_encryption = !password.is_empty();
        let input = if use_encryption {
            // 提供保险库名称 -> 选择加密 -> 输入密码 -> 确认密码
            format!("{}\ny\n{}\n{}\n", vault_name, password, password)
        } else {
            // 提供保险库名称 -> 选择不加密
            format!("{}\nn\n", vault_name)
        };

        // 4. 执行命令并断言成功
        cmd.write_stdin(input).assert().success();

        Ok(TestContext {
            _temp_dir: temp_dir,
            vault_path,
        })
    }

    /// Returns the path to the temporary directory.
    //
    // // 返回临时目录的路径。
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        self._temp_dir.path()
    }
}
