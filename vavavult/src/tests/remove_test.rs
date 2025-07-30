use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use crate::vault::{QueryResult, Vault};

#[test]
fn test_remove_file() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let mut vault = Vault::create_vault(vault_path, "test_vault").unwrap();

    let source_file_path = vault_path.join("delete_me.txt");
    File::create(&source_file_path).unwrap().write_all(b"delete content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("to_be_deleted.txt")).unwrap();

    // 确认文件已添加
    let internal_path = vault.root_path.join(&sha256sum);
    assert!(internal_path.exists());
    assert!(matches!(vault.find_by_hash( &sha256sum).unwrap(), QueryResult::Found(_)));

    // 2. 执行删除操作
    let remove_result = vault.remove_file(&sha256sum);
    assert!(remove_result.is_ok());

    // 3. 验证结果
    // 物理文件应被删除
    assert!(!internal_path.exists());
    // 数据库记录应被删除
    let query_result = vault.find_by_hash(&sha256sum).unwrap();
    assert!(matches!(query_result, QueryResult::NotFound));
}