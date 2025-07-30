use std::fs;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use crate::vault;
use crate::vault::QueryError;

#[test]
fn test_query_file_missing_from_disk_error() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let mut vault = vault::create_vault(vault_path, "test_vault").unwrap();

    let source_file_path = vault_path.join("my_file.txt");
    File::create(&source_file_path).unwrap().write_all(b"i will be deleted").unwrap();
    let sha256sum = vault.add_file(&source_file_path, None).unwrap();

    // 2. 手动删除物理文件，制造不一致状态
    let internal_path = vault.root_path.join(&sha256sum);
    fs::remove_file(internal_path).unwrap();

    // 3. 执行查询并断言错误类型
    let result = vault.find_by_hash(&sha256sum);
    assert!(matches!(result, Err(QueryError::FileMissing(_))));
}