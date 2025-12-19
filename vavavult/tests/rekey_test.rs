use std::fs;
use std::io::Write;
use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::{OpenError, QueryResult, UpdateError, Vault, update_password};

// 引入 common 模块，它提供了 setup_vault, setup_encrypted_vault 等辅助函数
mod common;

#[test]
fn test_rekey_file_e2e() {
    // 1. Arrange: 创建一个加密的保险库并添加一个文件
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let content = b"This is the content of the file to be re-keyed.";

    // 创建一个临时源文件
    let mut source_file = tempfile::NamedTempFile::new().unwrap();
    source_file.write_all(content).unwrap();
    let source_path = source_file.path();

    let dest_path = VaultPath::from("/rekey_test.txt");

    // 添加文件
    let old_hash = vault.add_file(source_path, &dest_path).unwrap();

    // 从数据库中获取完整的 FileEntry
    let old_entry = match vault.find_by_hash(&old_hash).unwrap() {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => panic!("File should have been added"),
    };

    // 2. Act: 执行密钥轮换
    let rekey_task = vault.prepare_rekey_task(&old_entry).unwrap();
    let new_hash = rekey_task.new_file_entry.sha256sum.clone();

    // 确认新旧哈希不同
    assert_ne!(old_hash, new_hash);

    vault.execute_rekey_tasks(vec![rekey_task]).unwrap();

    // 3. Assert: 验证轮换结果

    // a. 使用旧哈希查询应该失败
    assert!(matches!(
        vault.find_by_hash(&old_hash).unwrap(),
        QueryResult::NotFound
    ));

    // b. 使用新哈希查询应该成功
    let new_entry = match vault.find_by_hash(&new_hash).unwrap() {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => panic!("File should be found with new hash"),
    };

    // c. 验证新条目的元数据是否正确
    assert_eq!(new_entry.sha256sum, new_hash);
    assert_eq!(new_entry.path, dest_path);
    assert_eq!(new_entry.original_sha256sum, old_entry.original_sha256sum);
    assert_ne!(new_entry.encrypt_password, old_entry.encrypt_password);

    // d. 提取文件并验证内容
    let extracted_file_path = vault_path.join("extracted.txt");
    vault.extract_file(&new_hash, &extracted_file_path).unwrap();

    let extracted_content = fs::read(&extracted_file_path).unwrap();
    assert_eq!(extracted_content, content);
}

#[test]
fn update_password_e2e() {
    // 1. Arrange: 创建一个带密码的保险库并添加文件
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault_with_password(&dir, "password123");
    let content = b"some secret content";

    let mut source_file = tempfile::NamedTempFile::new().unwrap();
    source_file.write_all(content).unwrap();
    let source_path = source_file.path();
    let dest_path = VaultPath::from("/secret.txt");

    let file_hash = vault.add_file(source_path, &dest_path).unwrap();
    // Drop the vault to release the file lock
    drop(vault);

    // 2. Act: 更新密码
    let result = update_password(&vault_path, "password123", "new_password_456");
    if let Err(e) = &result {
        panic!("update_password failed with: {:?}", e);
    }
    assert!(result.is_ok());

    // 3. Assert:
    // a. 使用新密码可以成功打开
    let vault_after_update =
        Vault::open_vault_local(&vault_path, Some("new_password_456")).unwrap();

    // b. 确认文件仍然存在且可访问
    let entry_after_update = match vault_after_update.find_by_hash(&file_hash).unwrap() {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => panic!("File should still exist after password update"),
    };
    assert_eq!(entry_after_update.path.as_str(), "/secret.txt");

    // c. 提取并验证文件内容
    let extracted_path = dir.path().join("extracted_secret.txt");
    vault_after_update
        .extract_file(&file_hash, &extracted_path)
        .unwrap();
    let extracted_content = fs::read(extracted_path).unwrap();
    assert_eq!(&content[..], extracted_content.as_slice());

    drop(vault_after_update);

    // d. 使用旧密码打开应该失败
    let open_with_old_pass = Vault::open_vault_local(&vault_path, Some("password123"));
    assert!(matches!(
        open_with_old_pass,
        Err(OpenError::InvalidPassword)
    ));

    // e. 使用错误的旧密码更新应该失败
    let update_with_wrong_pass =
        update_password(&vault_path, "wrong_old_password", "another_password");
    assert!(matches!(
        update_with_wrong_pass,
        Err(UpdateError::InvalidOldPassword)
    ));
}
