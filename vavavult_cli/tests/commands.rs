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
use std::fs;

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
                .and(predicate::str::contains("Total Files:    0(0)")),
        );

    Ok(())
}

#[test]
fn test_remove_missing_storage_file() -> anyhow::Result<()> {
    // 1. Setup: Create vault and add a file
    let context = TestContext::new("missing-storage-rm-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    // 2. Get file hash and manually delete physical file to create inconsistency
    let (hash, _) = context.get_file_hash_and_path("/test_file.txt")?;
    let physical_file_path = context.get_physical_file_path(&hash);
    assert!(
        physical_file_path.exists(),
        "Physical file should exist after adding."
    );
    std::fs::remove_file(&physical_file_path)?;
    assert!(
        !physical_file_path.exists(),
        "Physical file should be deleted."
    );

    // 3. Attempt normal `rm` without confirmation - it should reach the prompt and cancel.
    let mut cmd_fail = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_fail.arg("open").arg(&context.vault_path);
    let repl_input_fail = "rm /test_file.txt\nexit\n".to_string();

    cmd_fail
        .write_stdin(repl_input_fail)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Are you sure you want to PERMANENTLY DELETE file '/test_file.txt'?",
        ))
        .stdout(predicate::str::contains("Operation cancelled."));

    // 4. Attempt normal `rm -y` - DB-first removal should succeed even when storage is missing.
    let mut cmd_remove = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_remove.arg("open").arg(&context.vault_path);
    let repl_input_remove = "rm -y /test_file.txt\nls /\nexit\n".to_string();

    cmd_remove
        .write_stdin(repl_input_remove)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 file(s) successfully deleted"))
        .stdout(predicate::str::contains("(empty)")); // Verify the file is gone

    Ok(())
}

#[test]
fn test_move_accepts_only_vault_path_source() -> anyhow::Result<()> {
    let context = TestContext::new("move-path-only-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    let (hash, _) = context.get_file_hash_and_path("/test_file.txt")?;

    // 1. 哈希源必须被拒绝，避免 mv 继续接受非路径目标。
    let mut cmd_hash = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_hash.arg("open").arg(&context.vault_path);
    let repl_input_hash = format!("mv {} /hash_moved.txt\nexit\n", hash);

    cmd_hash
        .write_stdin(repl_input_hash)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "The mv command only accepts source paths starting with '/'",
        ));

    // 2. 保险库路径源仍然可以正常移动。
    let mut cmd_path = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_path.arg("open").arg(&context.vault_path);
    let repl_input_path = "mv /test_file.txt /path_moved.txt\nls /\nexit\n".to_string();

    cmd_path
        .write_stdin(repl_input_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("File successfully moved."))
        .stdout(predicate::str::contains("/path_moved.txt"));

    Ok(())
}

#[test]
fn test_move_file_to_directory_keeps_original_name() -> anyhow::Result<()> {
    let context = TestContext::new("move-file-to-directory-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd.arg("open").arg(&context.vault_path);
    let repl_input = "mv /test_file.txt /docs/\nls /docs/\nls /\nexit\n".to_string();

    cmd.write_stdin(repl_input)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Moving file '/test_file.txt' to '/docs/test_file.txt'",
        ))
        .stdout(predicate::str::contains("/docs/test_file.txt"))
        .stdout(predicate::str::contains("/docs/"));

    Ok(())
}

#[test]
fn test_rename_accepts_only_vault_path_source() -> anyhow::Result<()> {
    let context = TestContext::new("rename-path-only-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    let (hash, _) = context.get_file_hash_and_path("/test_file.txt")?;

    // 1. 哈希源必须被拒绝，避免 rename 继续接受非路径目标。
    let mut cmd_hash = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_hash.arg("open").arg(&context.vault_path);
    let repl_input_hash = format!("rename {} renamed.txt\nexit\n", hash);

    cmd_hash
        .write_stdin(repl_input_hash)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "The rename command only accepts source paths starting with '/'",
        ));

    // 2. 保险库路径源仍然可以正常重命名。
    let mut cmd_path = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_path.arg("open").arg(&context.vault_path);
    let repl_input_path = "rename /test_file.txt renamed.txt\nls /\nexit\n".to_string();

    cmd_path
        .write_stdin(repl_input_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Path successfully renamed."))
        .stdout(predicate::str::contains("/renamed.txt"));

    Ok(())
}

#[test]
fn test_copy_file_to_directory_keeps_original_name() -> anyhow::Result<()> {
    let context = TestContext::new("copy-file-to-directory-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd.arg("open").arg(&context.vault_path);
    let repl_input = "copy /test_file.txt /copies/\nls /copies/\nls /\nexit\n".to_string();

    cmd.write_stdin(repl_input)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Copying file '/test_file.txt' to '/copies/test_file.txt'",
        ))
        .stdout(predicate::str::contains("/copies/test_file.txt"))
        .stdout(predicate::str::contains("/test_file.txt"));

    Ok(())
}

#[test]
fn test_copy_accepts_only_vault_path_source() -> anyhow::Result<()> {
    let context = TestContext::new("copy-path-only-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    let (hash, _) = context.get_file_hash_and_path("/test_file.txt")?;

    // 1. 哈希源必须被拒绝，copy/cp 只通过路径复制文件映射。
    let mut cmd_hash = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_hash.arg("open").arg(&context.vault_path);
    let repl_input_hash = format!("copy {} /hash_copy.txt\nexit\n", hash);

    cmd_hash
        .write_stdin(repl_input_hash)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "The copy command only accepts source paths starting with '/'",
        ));

    // 2. 主命令、cp 别名和兼容拼写 cpoy 都能通过路径复制。
    let mut cmd_path = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_path.arg("open").arg(&context.vault_path);
    let repl_input_path = concat!(
        "copy /test_file.txt /copy_a.txt\n",
        "cp /test_file.txt /copy_b.txt\n",
        "cpoy /test_file.txt /copy_c.txt\n",
        "ls /\n",
        "exit\n"
    )
    .to_string();

    cmd_path
        .write_stdin(repl_input_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("File successfully copied."))
        .stdout(predicate::str::contains("/copy_a.txt"))
        .stdout(predicate::str::contains("/copy_b.txt"))
        .stdout(predicate::str::contains("/copy_c.txt"));

    Ok(())
}

#[test]
fn test_remove_all_paths_by_hash() -> anyhow::Result<()> {
    let context = TestContext::new("remove-hash-all-paths-vault", "")?;
    context.add_file("test_file.txt", "some content", Some("/test_file.txt"))?;

    let (hash, _) = context.get_file_hash_and_path("/test_file.txt")?;

    // 1. 先通过 copy 产生同一哈希的多个路径映射。
    let mut cmd_copy = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_copy.arg("open").arg(&context.vault_path);
    cmd_copy
        .write_stdin("copy /test_file.txt /copy.txt\nexit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("File successfully copied."));

    // 2. 按哈希删除必须移除该哈希对应的所有文件路径。
    let mut cmd_remove = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_remove.arg("open").arg(&context.vault_path);
    let repl_input = format!("rm -y {}\nls /\nexit\n", hash);

    cmd_remove
        .write_stdin(repl_input)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 file(s) successfully deleted"))
        .stdout(predicate::str::contains("(empty)"));

    Ok(())
}

#[test]
fn test_remove_empty_directory_path() -> anyhow::Result<()> {
    let context = TestContext::new("remove-empty-directory-vault", "")?;
    let local_empty_dir = context.path().join("empty_dir");
    fs::create_dir(&local_empty_dir)?;

    // 1. 添加空本地目录会在保险库中创建空路径。
    let mut cmd_add = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_add.arg("open").arg(&context.vault_path);
    let add_input = format!(
        "add \"{}\" -p /empty/\nls /\nexit\n",
        local_empty_dir.display()
    );

    cmd_add
        .write_stdin(add_input)
        .assert()
        .success()
        .stdout(predicate::str::contains("/empty/"));

    // 2. rm -r 应删除空目录本身，而不是因没有文件而跳过。
    let mut cmd_remove = Command::new(env!("CARGO_BIN_EXE_vavavult"));
    cmd_remove.arg("open").arg(&context.vault_path);
    let remove_input = "rm -r -y /empty/\nls /\nexit\n".to_string();

    cmd_remove
        .write_stdin(remove_input)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 file(s) successfully deleted"))
        .stdout(predicate::str::contains("(empty)"));

    Ok(())
}
