//!
//! # CLI Command Integration Tests
//!
//! This file contains integration tests for the `vavavult_cli` commands,
//! utilizing the common test framework.
//!
//
// // # CLI 命令集成测试
// //
// // 此文件包含 `vavavult_cli` 命令的集成测试，
// // 并利用了通用的测试框架。
// //

// 引入通用测试模块
mod common;

use crate::common::TestContext;
use assert_cmd::Command;
use predicates::prelude::*;

/// Tests the complete lifecycle of creating a vault and checking its status.
///
/// This test performs the following steps:
/// 1. Creates a new, non-encrypted vault named "test-vault" using the `TestContext`.
///    This implicitly tests the `create` command's interactive flow.
/// 2. Runs the `open` command on the newly created vault.
/// 3. Pipes two commands into the REPL: `vault status` and `exit`.
/// 4. Asserts that the process exits successfully.
/// 5. Validates that the output of `vault status` contains the correct vault name
///    and the initial file count (0).
//
// // 测试创建保险库并检查其状态的完整生命周期。
// //
// // 此测试执行以下步骤：
// // 1. 使用 `TestContext` 创建一个名为 "test-vault" 的新的、未加密的保险库。
// //    这将隐式地测试 `create` 命令的交互流程。
// // 2. 在新创建的保险库上运行 `open` 命令。
// // 3. 将两个命令通过管道送入 REPL：`vault status` 和 `exit`。
// // 4. 断言进程成功退出。
// // 5. 验证 `vault status` 的输出包含正确的保险库名称和初始文件计数（0）。
#[test]
fn test_vault_creation_and_status() -> anyhow::Result<()> {
    // 1. 使用 TestContext 创建一个干净的保险库环境
    // 这会调用 `vavavult create` 并处理交互
    let context = TestContext::new("test-vault", "")?;

    // 2. 准备 open 命令以进入 REPL
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd.arg("open").arg(&context.vault_path);

    // 3. 准备要送入 REPL 的指令
    let repl_input = "vault status\nexit\n".to_string();

    // 4. 运行命令并进行断言
    cmd.write_stdin(repl_input)
        .assert()
        .success() // 断言进程成功退出
        .stdout(
            // 断言标准输出包含预期的内容
            predicate::str::contains("Vault 'test-vault' is now open.")
                .and(predicate::str::contains("Name:           test-vault"))
                .and(predicate::str::contains("Total Files:    0")),
        );

    Ok(())
}
