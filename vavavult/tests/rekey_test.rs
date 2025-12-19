use std::fs;
use std::io::Write;
use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::QueryResult;

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
