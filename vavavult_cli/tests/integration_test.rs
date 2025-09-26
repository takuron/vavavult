use std::process::{Command, Stdio, ChildStdin};
use std::io::Write;
use tempfile::tempdir;
use std::fs;
use std::thread;
use std::time::Duration;

/// 辅助函数：找到 `cargo test` 编译出的二进制文件路径。
fn get_cli_binary() -> std::path::PathBuf {
    // This helper function locates the binary compiled by `cargo test`
    // It's a reliable way to get the executable's path in a test environment.
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("vavavult_cli")
}

/// 辅助函数：向子进程的 stdin 写入一行命令，并等待一小会儿。
fn write_to_stdin(stdin: &mut ChildStdin, line: &str) {
    stdin.write_all(line.as_bytes()).expect("Failed to write to stdin");
    stdin.flush().expect("Failed to flush stdin");
    // A small delay to ensure the REPL has time to process the command
    thread::sleep(Duration::from_millis(300));
}

/// 综合测试场景：模拟一个完整的用户生命周期。
#[test]
fn test_full_lifecycle_integration() {
    // 1. 准备环境 (Setup)
    let dir = tempdir().unwrap();
    let file1_path = dir.path().join("file1.txt");
    fs::write(&file1_path, "content1").unwrap();
    let extract_dir = dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    // 2. 启动子进程 (Start the CLI process)
    let mut child = Command::new(get_cli_binary())
        .arg("create")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start CLI process");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");

    // 3. 逐行写入指令 (Write commands line-by-line)

    // 创建保险库
    write_to_stdin(&mut stdin, "full-cycle-vault\n");
    write_to_stdin(&mut stdin, "n\n");

    // **关键修正**: 将路径用双引号括起来，防止路径中的空格或特殊字符导致问题。
    // 使用 `replace` 将 `\` 替换为 `/` 是一种非常稳健的跨平台测试策略。
    let sanitized_add_path = file1_path.to_string_lossy().replace("\\", "/");
    let sanitized_extract_path = extract_dir.to_string_lossy().replace("\\", "/");

    // 添加文件
    write_to_stdin(&mut stdin, &format!("add \"{}\" -n /doc/file1.txt\n", sanitized_add_path));
    // 添加标签
    write_to_stdin(&mut stdin, "tag add -n /doc/file1.txt important\n");
    // 按标签列出
    write_to_stdin(&mut stdin, "list --tag important\n");
    // 提取文件
    write_to_stdin(&mut stdin, &format!("extract -n /doc/file1.txt \"{}\"\n", sanitized_extract_path));
    // 删除文件
    write_to_stdin(&mut stdin, "remove -n /doc/file1.txt\n");
    // 确认删除
    write_to_stdin(&mut stdin, "Y\n");
    // 再次列出 (应为空)
    write_to_stdin(&mut stdin, "list\n");
    // 退出
    write_to_stdin(&mut stdin, "exit\n");

    // 4. 等待并捕获输出 (Wait and capture output)
    let output = child.wait_with_output().expect("Failed to wait for child process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("--- STDOUT ---\n{}\n--------------", stdout);
    println!("--- STDERR ---\n{}\n--------------", stderr);

    // 5. 断言 (Assert results)
    assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);

    assert!(stdout.contains("Successfully added file."));
    assert!(stdout.contains("Tags added successfully."));
    assert!(stdout.contains("/doc/file1.txt")); // from `list --tag`
    assert!(stdout.contains("File extracted successfully."));
    assert!(stdout.contains("File successfully deleted."));

    // 6. 验证文件系统 (Verify filesystem state)
    let extracted_file = extract_dir.join("file1.txt");
    assert!(extracted_file.exists(), "The file was not extracted to the filesystem!");
    assert_eq!(fs::read_to_string(extracted_file).unwrap(), "content1");
}

#[test]
fn test_create_non_encrypted_vault() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("my-test-vault");

    let mut child = Command::new(get_cli_binary())
        .arg("create")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start CLI process");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    write_to_stdin(&mut stdin, "my-test-vault\n");
    write_to_stdin(&mut stdin, "n\n");
    write_to_stdin(&mut stdin, "exit\n");

    let output = child.wait_with_output().expect("Failed to wait for child process");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Vault 'my-test-vault' is now open."));

    assert!(vault_path.exists());
    assert!(vault_path.join("master.json").exists());
}

// --- 全新重写的、基于实际输出的并行操作集成测试 ---
#[test]
fn test_parallel_add_and_extract_lifecycle() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let source_dir = dir.path().join("source_files");
    fs::create_dir_all(&source_dir).unwrap();
    let extract_dir = dir.path().join("extracted_files");
    let extract_and_delete_dir = dir.path().join("extract_and_delete_files");

    // 创建 10 个小文件
    for i in 0..10 {
        fs::write(source_dir.join(format!("file_{}.txt", i)), format!("content_{}", i)).unwrap();
    }

    // 准备跨平台的路径字符串
    let vault_parent_path = dir.path().to_string_lossy().replace('\\', "/");
    let sanitized_source_path = source_dir.to_string_lossy().replace('\\', "/");
    let sanitized_extract_path = extract_dir.to_string_lossy().replace('\\', "/");
    let sanitized_extract_delete_path = extract_and_delete_dir.to_string_lossy().replace('\\', "/");

    // 2. 启动 CLI 进程
    let mut child = Command::new(get_cli_binary())
        .arg("create")
        .arg(&vault_parent_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start CLI process");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");

    // 3. 自动化命令序列
    write_to_stdin(&mut stdin, "parallel-vault\n");
    write_to_stdin(&mut stdin, "n\n");

    // 并行添加 (目标是 vault 的根目录)
    write_to_stdin(&mut stdin, &format!("add \"{}\" --parallel\n", sanitized_source_path));
    write_to_stdin(&mut stdin, "y\n");

    // 列出以验证
    write_to_stdin(&mut stdin, "list\n");

    // 并行提取 (从 vault 的根目录递归提取)
    write_to_stdin(&mut stdin, &format!("extract -d / --recursive --parallel \"{}\"\n", sanitized_extract_path));
    write_to_stdin(&mut stdin, "y\n");

    // 并行提取并删除
    write_to_stdin(&mut stdin, &format!("extract -d / --recursive --parallel --delete \"{}\"\n", sanitized_extract_delete_path));
    write_to_stdin(&mut stdin, "y\n");
    write_to_stdin(&mut stdin, "y\n");

    // 再次列出以验证删除
    write_to_stdin(&mut stdin, "list\n");

    write_to_stdin(&mut stdin, "exit\n");

    // 4. 捕获输出
    let output = child.wait_with_output().expect("Failed to wait for child process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("--- PARALLEL STDOUT ---\n{}\n--------------", stdout);
    println!("--- PARALLEL STDERR ---\n{}\n--------------", stderr);

    // 5. 断言
    assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);

    // Validate adding
    assert!(stdout.contains("Batch add complete. 10 succeeded, 0 failed."));

    // Validate first list
    assert!(stdout.contains("/file_9.txt"));

    // Validate extraction
    assert!(stdout.contains("10 succeeded, 0 failed."));

    // Validate second list (should be empty)
    assert!(stdout.contains("All 0 file(s) in the vault:") || stdout.contains("(empty)"));


    // 6. 验证文件系统
    for i in 0..10 {
        let filename = format!("file_{}.txt", i);
        let content = format!("content_{}", i);

        // 检查第一次提取的文件 (直接在目标目录下)
        let extracted_file = extract_dir.join(&filename);
        assert!(extracted_file.exists(), "File {} was not extracted correctly!", filename);
        assert_eq!(fs::read_to_string(extracted_file).unwrap(), content);

        // 检查第二次提取的文件
        let extracted_deleted_file = extract_and_delete_dir.join(&filename);
        assert!(extracted_deleted_file.exists(), "File {} was not extracted correctly before delete!", filename);
        assert_eq!(fs::read_to_string(extracted_deleted_file).unwrap(), content);
    }
}