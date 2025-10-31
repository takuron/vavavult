// use std::process::{Command, Stdio, Child, ChildStdin};
// use std::io::{Write, ErrorKind};
// use tempfile::{tempdir, TempDir};
// use std::fs;
// use std::thread;
// use std::time::Duration;
// use std::path::PathBuf;
//
// /// 辅助函数：找到 `cargo test` 编译出的二进制文件路径。
// fn get_cli_binary() -> std::path::PathBuf {
//     let mut path = std::env::current_exe().unwrap();
//     path.pop();
//     if path.ends_with("deps") {
//         path.pop();
//     }
//     path.join("vavavult_cli")
// }
//
// /// [MODIFIED] 辅助函数：向子进程的 stdin 写入一行命令，并等待一小会儿。
// /// 增加了对 BrokenPipe 的更明确的恐慌信息，并增加了延迟。
// fn write_to_stdin(stdin: &mut ChildStdin, line: &str) {
//     match stdin.write_all(line.as_bytes()) {
//         Ok(_) => {
//             stdin.flush().expect("Failed to flush stdin");
//             // [FIX] 增加延迟以提高稳定性，应对 I/O 和 WalkDir 扫描
//             thread::sleep(Duration::from_millis(800));
//         }
//         Err(e) if e.kind() == ErrorKind::BrokenPipe => {
//             panic!(
//                 "Failed to write to stdin ('{}'): BrokenPipe. The CLI process died unexpectedly. Check previous commands for panics or errors.",
//                 line.trim()
//             );
//         }
//         Err(e) => {
//             panic!("Failed to write to stdin: {}", e);
//         }
//     }
// }
//
// /// 辅助函数：清理路径以便在 Windows 和 Unix 上都能在 CLI 中使用
// fn sanitize_path(path: &PathBuf) -> String {
//     path.to_string_lossy().replace('\\', "/")
// }
//
// /// 辅助函数：启动一个 CLI 实例，创建一个保险库，并添加3个标准文件
// ///
// /// 保险库结构:
// /// /file_a.txt
// /// /docs/file_b.md
// /// /docs/deep/file_c.jpg
// fn setup_vault_with_files() -> (Child, ChildStdin, TempDir) {
//     // 1. 准备环境
//     let dir = tempdir().unwrap();
//     let file_a_path = dir.path().join("file_a.txt");
//     fs::write(&file_a_path, "content a").unwrap();
//
//     let docs_dir = dir.path().join("docs");
//     fs::create_dir_all(&docs_dir).unwrap();
//     let file_b_path = docs_dir.join("file_b.md");
//     fs::write(&file_b_path, "content b").unwrap();
//
//     let deep_dir = docs_dir.join("deep");
//     fs::create_dir_all(&deep_dir).unwrap();
//     let file_c_path = deep_dir.join("file_c.jpg");
//     fs::write(&file_c_path, "content c").unwrap();
//
//     // 2. 启动子进程
//     let mut child = Command::new(get_cli_binary())
//         .arg("create")
//         .arg(dir.path())
//         .stdin(Stdio::piped())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .expect("Failed to start CLI process");
//
//     let mut stdin = child.stdin.take().expect("Failed to open stdin");
//
//     // 3. 自动化保险库创建
//     write_to_stdin(&mut stdin, "test-vault\n"); // Vault name
//     write_to_stdin(&mut stdin, "n\n"); // No encryption
//
//     // 4. 添加文件 (这些是单文件添加，不需要确认)
//     write_to_stdin(&mut stdin, &format!("add \"{}\" -p /file_a.txt\n", sanitize_path(&file_a_path)));
//     write_to_stdin(&mut stdin, &format!("add \"{}\" -p /docs/file_b.md\n", sanitize_path(&file_b_path)));
//     write_to_stdin(&mut stdin, &format!("add \"{}\" -p /docs/deep/file_c.jpg\n", sanitize_path(&file_c_path)));
//
//     (child, stdin, dir)
// }
//
//
// // --- 分项测试 ---
//
// #[test]
// fn test_list_and_search_commands() {
//     let (mut child, mut stdin, _dir) = setup_vault_with_files();
//
//     // 测试 `ls`
//     write_to_stdin(&mut stdin, "ls /\n");
//     // 测试 `ls -l` (详细)
//     write_to_stdin(&mut stdin, "ls -l /docs/\n");
//     // 测试 `ls -R` (递归)
//     write_to_stdin(&mut stdin, "ls -R /\n");
//     // 测试 `ls` (单个文件)
//     write_to_stdin(&mut stdin, "ls /file_a.txt\n");
//     // 测试 `search`
//     write_to_stdin(&mut stdin, "search deep\n");
//
//     write_to_stdin(&mut stdin, "exit\n");
//
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     // `ls /`
//     assert!(stdout.contains("[docs/]"));
//     assert!(stdout.contains("file_a.txt"));
//     // `ls -l /docs/`
//     assert!(stdout.contains("Name:    file_b.md"));
//     assert!(stdout.contains("Name:    deep"));
//     // `ls -R /`
//     assert!(stdout.contains("/file_a.txt"));
//     assert!(stdout.contains("/docs/file_b.md"));
//     assert!(stdout.contains("/docs/deep/file_c.jpg"));
//     // `ls /file_a.txt`
//     assert!(stdout.contains("Path:    /file_a.txt"));
//     // `search deep`
//     assert!(stdout.contains("Found 1 file(s) matching 'deep'"));
//     assert!(stdout.contains("/docs/deep/file_c.jpg"));
// }
//
// #[test]
// fn test_move_and_rename_commands() {
//     let (mut child, mut stdin, _dir) = setup_vault_with_files();
//
//     // 1. `mv` (文件到目录)
//     write_to_stdin(&mut stdin, "mv -p /file_a.txt /docs/\n");
//     // 2. `mv` (文件到文件，即移动并重命名)
//     write_to_stdin(&mut stdin, "mv -p /docs/file_b.md /file_b_moved.md\n");
//     // 3. `rename` (就地重命名)
//     write_to_stdin(&mut stdin, "rename -p /file_b_moved.md file_b_renamed.md\n");
//     // 4. 验证
//     write_to_stdin(&mut stdin, "ls -R /\n");
//
//     write_to_stdin(&mut stdin, "exit\n");
//
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     assert!(stdout.contains("File successfully moved."));
//     assert!(stdout.contains("File successfully renamed."));
//
//     // 验证最终状态
//     let final_ls = stdout.lines().skip_while(|&l| !l.contains("vavavult[test-vault]> ls -R /")).collect::<String>();
//     assert!(final_ls.contains("/docs/file_a.txt"));
//     assert!(final_ls.contains("/file_b_renamed.md"));
//     assert!(final_ls.contains("/docs/deep/file_c.jpg"));
//     assert!(!final_ls.contains("/file_a.txt"));
//     assert!(!final_ls.contains("/docs/file_b.md"));
// }
//
// #[test]
// fn test_tag_commands() {
//     let (mut child, mut stdin, _dir) = setup_vault_with_files();
//
//     // 1. `tag add -p` (文件)
//     write_to_stdin(&mut stdin, "tag add -p /file_a.txt tag1 important\n");
//     write_to_stdin(&mut stdin, "y\n");
//     // 2. `tag add -p` (目录，自动递归)
//     write_to_stdin(&mut stdin, "tag add -p /docs/ doc_tag\n");
//     write_to_stdin(&mut stdin, "y\n");
//     // 3. `search` 验证
//     write_to_stdin(&mut stdin, "search tag1\n");
//     write_to_stdin(&mut stdin, "search doc_tag\n");
//     // 4. `tag remove -p` (文件)
//     write_to_stdin(&mut stdin, "tag remove -p /docs/deep/file_c.jpg doc_tag\n");
//     write_to_stdin(&mut stdin, "y\n");
//     // 5. `tag clear -p` (文件)
//     write_to_stdin(&mut stdin, "tag clear -p /file_a.txt\n");
//     write_to_stdin(&mut stdin, "y\n");
//     // 6. 验证
//     write_to_stdin(&mut stdin, "search doc_tag\n");
//     write_to_stdin(&mut stdin, "search tag1\n");
//
//
//     write_to_stdin(&mut stdin, "exit\n");
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     // 验证 `tag add`
//     assert!(stdout.contains("Add tags [tag1, important] to file '/file_a.txt'"));
//     assert!(stdout.contains("Add tags [doc_tag] to 2 files from directory '/docs/' (recursive)"));
//     // 验证 `search`
//     assert!(stdout.contains("Found 1 file(s) matching 'tag1'"));
//     assert!(stdout.contains("/file_a.txt"));
//     assert!(stdout.contains("Found 2 file(s) matching 'doc_tag'"));
//     assert!(stdout.contains("/docs/file_b.md"));
//     assert!(stdout.contains("/docs/deep/file_c.jpg"));
//
//     // 验证 `tag remove`
//     assert!(stdout.contains("Remove tags [doc_tag] from file '/docs/deep/file_c.jpg'"));
//     // 验证 `tag clear`
//     assert!(stdout.contains("clear ALL tags from file '/file_a.txt'"));
//
//     // 验证最终搜索
//     assert!(stdout.contains("Found 1 file(s) matching 'doc_tag'"));
//     assert!(!stdout.contains("/docs/deep/file_c.jpg")); // 已移除
//     assert!(stdout.contains("No files found matching 'tag1'"));
// }
//
// #[test]
// fn test_remove_commands() {
//     let (mut child, mut stdin, _dir) = setup_vault_with_files();
//
//     // 1. `rm -p` (目录, 无 -r) -> 应该失败
//     write_to_stdin(&mut stdin, "rm -p /docs/\n");
//     // 2. `rm -p` (文件, 需确认)
//     write_to_stdin(&mut stdin, "rm -p /file_a.txt\n");
//     write_to_stdin(&mut stdin, "y\n");
//     // 3. `rm -r -f -p` (目录, 递归, 强制)
//     write_to_stdin(&mut stdin, "rm -r -f -p /docs/\n");
//     // 4. 验证
//     write_to_stdin(&mut stdin, "ls /\n");
//     write_to_stdin(&mut stdin, "vault status\n");
//
//     write_to_stdin(&mut stdin, "exit\n");
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     // 1. 验证目录删除失败
//     assert!(stdout.contains("Error: Cannot remove '/docs/': It is a directory. Use -r (recursive) to delete."));
//     // 2. 验证文件删除成功
//     assert!(stdout.contains("PERMANENTLY DELETE file '/file_a.txt'"));
//     assert!(stdout.contains("1 file(s) successfully deleted."));
//     // 3. 验证递归删除
//     assert!(stdout.contains("PERMANENTLY DELETE 2 files from directory '/docs/' (recursive)"));
//     assert!(stdout.contains("2 file(s) successfully deleted."));
//     // 4. 验证最终状态
//     assert!(stdout.contains("(empty)"));
//     assert!(stdout.contains("Total Files:    0"));
// }
//
// #[test]
// fn test_vault_commands() {
//     let (mut child, mut stdin, _dir) = setup_vault_with_files();
//
//     // 1. `vault status`
//     write_to_stdin(&mut stdin, "vault status\n");
//     // 2. `vault rename`
//     write_to_stdin(&mut stdin, "vault rename new-name\n");
//     // 3. `vault status` (验证新名称)
//     write_to_stdin(&mut stdin, "vault status\n");
//
//     write_to_stdin(&mut stdin, "exit\n");
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     // 1. 验证初始状态
//     assert!(stdout.contains("Name:           test-vault"));
//     assert!(stdout.contains("Total Files:    3"));
//     // 2. 验证重命名
//     assert!(stdout.contains("Vault successfully renamed from 'test-vault' to 'new-name'."));
//     // 3. 验证新状态
//     assert!(stdout.contains("Name:           new-name"));
// }
//
//
// // --- 模拟测试 ---
//
// #[test]
// fn test_full_lifecycle_simulation() {
//     // 1. 准备环境
//     let dir = tempdir().unwrap();
//     let source_dir = dir.path().join("source_files");
//     fs::create_dir_all(&source_dir).unwrap();
//
//     let file_a_path = source_dir.join("file_a.txt");
//     fs::write(&file_a_path, "content for file A").unwrap();
//
//     let dir_b = source_dir.join("dir_b");
//     fs::create_dir_all(&dir_b).unwrap();
//     let file_b_path = dir_b.join("file_b.txt");
//     fs::write(&file_b_path, "content for file B").unwrap();
//
//     let extract_dir = dir.path().join("extracted");
//     fs::create_dir_all(&extract_dir).unwrap();
//
//     // 准备清理过的路径
//     let san_file_a = sanitize_path(&file_a_path);
//     let san_dir_b = sanitize_path(&dir_b);
//     let san_extract = sanitize_path(&extract_dir);
//
//     // 2. 启动子进程
//     let mut child = Command::new(get_cli_binary())
//         .arg("create")
//         .arg(dir.path())
//         .stdin(Stdio::piped())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .expect("Failed to start CLI process");
//
//     let mut stdin = child.stdin.take().expect("Failed to open stdin");
//
//     // 3. 逐行写入指令
//     write_to_stdin(&mut stdin, "life-cycle-vault\n"); // Vault name
//     write_to_stdin(&mut stdin, "n\n"); // No encryption
//
//     // `add` (文件) - 无需确认
//     write_to_stdin(&mut stdin, &format!("add \"{}\" -p /file_a.txt\n", san_file_a));
//     // `add` (目录) - 需要确认
//     write_to_stdin(&mut stdin, &format!("add \"{}\" -p /b_docs/\n", san_dir_b));
//     write_to_stdin(&mut stdin, "y\n");
//
//     // `ls -R`
//     write_to_stdin(&mut stdin, "ls -R\n");
//     // `vault status`
//     write_to_stdin(&mut stdin, "vault status\n");
//
//     // `tag add` (目录) - 需要确认
//     write_to_stdin(&mut stdin, "tag add -p /b_docs/ tag_b\n");
//     write_to_stdin(&mut stdin, "y\n");
//     // `search`
//     write_to_stdin(&mut stdin, "search tag_b\n");
//
//     // `mv` - 无需确认
//     write_to_stdin(&mut stdin, "mv -p /file_a.txt /a_moved.txt\n");
//
//     // `extract` (非 delete) - 无需确认
//     write_to_stdin(&mut stdin, &format!("extract -p /a_moved.txt \"{}\"\n", san_extract));
//
//     // `rm` (文件) - 需要确认
//     write_to_stdin(&mut stdin, "rm -p /a_moved.txt\n");
//     write_to_stdin(&mut stdin, "Y\n");
//
//     // `rm` (目录, 递归, 强制) - 无需确认
//     write_to_stdin(&mut stdin, "rm -r -f -p /b_docs/\n");
//
//     // `ls` (应为空)
//     write_to_stdin(&mut stdin, "ls\n");
//     // `vault status` (应为 0)
//     write_to_stdin(&mut stdin, "vault status\n");
//
//     // `exit`
//     write_to_stdin(&mut stdin, "exit\n");
//
//     // 4. 等待并捕获输出
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     println!("--- FULL LIFECYCLE STDOUT ---\n{}\n--------------", stdout);
//     println!("--- FULL LIFECYCLE STDERR ---\n{}\n--------------", stderr);
//
//     // 5. 断言
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     // Add
//     assert!(stdout.contains("Successfully added file.")); // add file
//     assert!(stdout.contains("Batch add complete. 1 succeeded, 0 failed.")); // Add dir
//     // Ls / Status
//     assert!(stdout.contains("/file_a.txt"));
//     assert!(stdout.contains("/b_docs/file_b.txt"));
//     assert!(stdout.contains("Total Files:    2"));
//     // Tag / Search
//     assert!(stdout.contains("Add tags [tag_b] to 1 files from directory '/b_docs/' (recursive)"));
//     assert!(stdout.contains("Found 1 file(s) matching 'tag_b'"));
//     // Mv
//     assert!(stdout.contains("File successfully moved."));
//     // Extract
//     assert!(stdout.contains("File extracted successfully."));
//     // Remove (File)
//     assert!(stdout.contains("PERMANENTLY DELETE file '/a_moved.txt'"));
//     assert!(stdout.contains("1 file(s) successfully deleted."));
//     // Remove (Dir)
//     assert!(stdout.contains("PERMANENTLY DELETE 1 files from directory '/b_docs/' (recursive)"));
//     assert!(stdout.contains("1 file(s) successfully deleted."));
//     // Final state
//     assert!(stdout.contains("(empty)"));
//     assert!(stdout.contains("Total Files:    0"));
//
//     // 6. 验证文件系统
//     let extracted_file = extract_dir.join("a_moved.txt");
//     assert!(extracted_file.exists(), "The file was not extracted!");
//     assert_eq!(fs::read_to_string(extracted_file).unwrap(), "content for file A");
// }
//
// #[test]
// fn test_parallel_add_and_extract_lifecycle() {
//     // 1. 准备环境
//     let dir = tempdir().unwrap();
//     let source_dir = dir.path().join("source_files");
//     fs::create_dir_all(&source_dir).unwrap();
//     let extract_dir = dir.path().join("extracted_files");
//     fs::create_dir_all(&extract_dir).unwrap();
//     let extract_and_delete_dir = dir.path().join("extract_and_delete_files");
//     fs::create_dir_all(&extract_and_delete_dir).unwrap();
//
//     // 创建 10 个小文件
//     for i in 0..10 {
//         fs::write(source_dir.join(format!("file_{}.txt", i)), format!("content_{}", i)).unwrap();
//     }
//
//     // 准备跨平台的路径字符串
//     let vault_parent_path = sanitize_path(&dir.path().to_path_buf());
//     let sanitized_source_path = sanitize_path(&source_dir);
//     let sanitized_extract_path = sanitize_path(&extract_dir);
//     let sanitized_extract_delete_path = sanitize_path(&extract_and_delete_dir);
//
//     // 2. 启动 CLI 进程
//     let mut child = Command::new(get_cli_binary())
//         .arg("create")
//         .arg(&vault_parent_path)
//         .stdin(Stdio::piped())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()
//         .expect("Failed to start CLI process");
//
//     let mut stdin = child.stdin.take().expect("Failed to open stdin");
//
//     // 3. 自动化命令序列
//     write_to_stdin(&mut stdin, "parallel-vault\n");
//     write_to_stdin(&mut stdin, "n\n");
//
//     // `add` (并行, 添加到根目录) - 需要确认
//     write_to_stdin(&mut stdin, &format!("add \"{}\" --parallel -p /\n", sanitized_source_path));
//     write_to_stdin(&mut stdin, "y\n");
//
//     // 列出以验证
//     write_to_stdin(&mut stdin, "ls\n");
//
//     // `extract` (并行, 递归) - 需要确认
//     write_to_stdin(&mut stdin, &format!("extract -p / --recursive --parallel \"{}\"\n", sanitized_extract_path));
//     write_to_stdin(&mut stdin, "y\n");
//
//     // `extract` (并行, 递归, 删除) - 需要 2 次确认
//     write_to_stdin(&mut stdin, &format!("extract -p / --recursive --parallel --delete \"{}\"\n", sanitized_extract_delete_path));
//     write_to_stdin(&mut stdin, "y\n"); // 确认提取
//     write_to_stdin(&mut stdin, "y\n"); // 确认删除
//
//     // 再次列出以验证删除
//     write_to_stdin(&mut stdin, "ls\n");
//     write_to_stdin(&mut stdin, "vault status\n");
//
//     write_to_stdin(&mut stdin, "exit\n");
//
//     // 4. 捕获输出
//     let output = child.wait_with_output().expect("Failed to wait for child process");
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let stderr = String::from_utf8_lossy(&output.stderr);
//
//     println!("--- PARALLEL STDOUT ---\n{}\n--------------", stdout);
//     println!("--- PARALLEL STDERR ---\n{}\n--------------", stderr);
//
//     // 5. 断言
//     assert!(output.status.success(), "CLI process exited with an error. Stderr:\n{}", stderr);
//
//     // Validate adding
//     assert!(stdout.contains("Batch add complete. 10 succeeded, 0 failed."));
//     // Validate first list
//     assert!(stdout.contains("file_9.txt"));
//     // Validate extraction
//     assert!(stdout.contains("10 succeeded, 0 failed.")); // 第一次
//     assert!(stdout.contains("10 succeeded, 0 failed.")); // 第二次
//
//     // Validate second list (should be empty)
//     assert!(stdout.contains("(empty)"));
//     assert!(stdout.contains("Total Files:    0"));
//
//
//     // 6. 验证文件系统
//     for i in 0..10 {
//         let filename = format!("file_{}.txt", i);
//         let content = format!("content_{}", i);
//
//         // 检查第一次提取的文件
//         let extracted_file = extract_dir.join(&filename);
//         assert!(extracted_file.exists(), "File {} was not extracted correctly!", filename);
//         assert_eq!(fs::read_to_string(extracted_file).unwrap(), content);
//
//         // 检查第二次提取的文件
//         let extracted_deleted_file = extract_and_delete_dir.join(&filename);
//         assert!(extracted_deleted_file.exists(), "File {} was not extracted correctly before delete!", filename);
//         assert_eq!(fs::read_to_string(extracted_deleted_file).unwrap(), content);
//     }
// }