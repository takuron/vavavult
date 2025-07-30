use crate::vault::{AddFileError, create_vault}; // 导入 create_vault 函数
use std::fs::File;
use std::io::Write;
use tempfile::tempdir; // 使用 tempfile 库来创建临时目录，避免弄乱文件系统
#[test]
fn test_add_file_successfully() {
    // 1. 准备环境
    let dir = tempdir().unwrap(); // 创建一个临时目录
    let vault_path = dir.path();
    let mut vault = create_vault(vault_path, "test_vault").unwrap();

    // 创建临时源文件
    let source_file_path1 = vault_path.join("my_test_file.txt");
    let mut source_file1 = File::create(&source_file_path1).unwrap();
    writeln!(source_file1, "Hello, Vault!").unwrap();

    let source_file_path2 = vault_path.join("my_test_file2.txt");
    let mut source_file2 = File::create(&source_file_path2).unwrap();
    writeln!(source_file2, "Hello, Vault New!").unwrap();

    // 2. 执行操作
    let result1 = vault.add_file(&source_file_path1, None);
    let result2 = vault.add_file(&source_file_path2, Some("/a/b/c/new_name.txt"));

    // 3. 断言结果
    assert!(result1.is_ok());
    assert!(result2.is_ok());
    let sha256sum1 = result1.unwrap();
    let sha256sum2 = result2.unwrap();

    // 4. 验证数据库
    let mut stmt = vault
        .database_connection
        .prepare("SELECT name FROM files WHERE sha256sum = ?1")
        .unwrap();
    let file_name1: String = stmt.query_row([&sha256sum1], |row| row.get(0)).unwrap();
    let file_name2: String = stmt.query_row([&sha256sum2], |row| row.get(0)).unwrap();

    assert_eq!(file_name1, "/my_test_file.txt");
    assert_eq!(file_name2, "/a/b/c/new_name.txt");

    // 验证文件是否已复制到目录
    let internal_path = vault.root_path.join(sha256sum1);
    assert!(internal_path.exists());
}

#[test]
fn test_add_duplicate_file_name() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let mut vault = create_vault(vault_path, "test_vault").unwrap();

    // 创建第一个文件
    let source_file_path1 = vault_path.join("file1.txt");
    File::create(&source_file_path1)
        .unwrap()
        .write_all(b"content1")
        .unwrap();
    vault
        .add_file(&source_file_path1, Some("shared_name.txt"))
        .unwrap();

    // 创建第二个内容不同的文件
    let source_file_path2 = vault_path.join("file2.txt");
    File::create(&source_file_path2)
        .unwrap()
        .write_all(b"content2")
        .unwrap();

    // 2. 执行操作 (尝试用同样的名字添加第二个文件)
    let result = vault.add_file(&source_file_path2, Some("shared_name.txt"));

    // 3. 断言结果
    assert!(matches!(result, Err(AddFileError::DuplicateFileName(_))));
}
