use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use crate::vault;
use crate::vault::QueryResult;

#[test]
fn test_rename_file() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let mut vault = vault::create_vault(vault_path, "test_vault").unwrap();

    let source_file_path = vault_path.join("rename_me.txt");
    File::create(&source_file_path).unwrap().write_all(b"rename content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("old_name.txt")).unwrap();

    // 2. 执行重命名操作
    let new_name = "new/path/to/file.txt";
    let rename_result = vault.rename_file(&sha256sum, new_name);
    assert!(rename_result.is_ok());

    // 3. 验证结果
    // 用旧名字查，应该找不到了
    let old_name_result = vault.find_by_name( "/old_name.txt").unwrap();
    assert!(matches!(old_name_result, QueryResult::NotFound));

    // 用新名字查，应该能找到
    let new_name_result = vault.find_by_name( "/new/path/to/file.txt").unwrap();
    if let QueryResult::Found(entry) = new_name_result {
        assert_eq!(entry.sha256sum, sha256sum);
    } else {
        panic!("File should be found by its new name");
    }

    // 尝试重命名为一个已存在的名字，应该会失败
    let other_file_path = vault_path.join("other.txt");
    File::create(&other_file_path).unwrap().write_all(b"other content").unwrap();
    vault.add_file(&other_file_path, Some("existing_name.txt")).unwrap();

    let failed_rename_result = vault.rename_file(&sha256sum, "existing_name.txt");
    assert!(matches!(failed_rename_result, Err(vault::UpdateError::DuplicateFileName(_))));
}

#[test]
fn test_tag_management() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let mut vault = vault::create_vault(vault_path, "test_vault").unwrap();

    let source_file_path = vault_path.join("tag_me.txt");
    File::create(&source_file_path).unwrap().write_all(b"tag content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("tagged_file.txt")).unwrap();

    // 2. 添加单个标签
    vault.add_tag(&sha256sum, "rust").unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert_eq!(entry.tags, vec!["rust"]);
    } else {
        panic!("File not found after adding a tag");
    }

    // 3. 批量添加标签 (包含一个已存在的)
    vault.add_tags( &sha256sum, &["project", "important", "rust"]).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        // 验证标签已排序且无重复
        assert_eq!(entry.tags, vec!["important", "project", "rust"]);
    } else {
        panic!("File not found after adding multiple tags");
    }

    // 4. 删除一个标签
    vault.remove_tag(&sha256sum, "project").unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash( &sha256sum).unwrap() {
        assert_eq!(entry.tags, vec!["important", "rust"]);
    } else {
        panic!("File not found after removing a tag");
    }

    // 5. 删除所有标签
    vault.clear_tags(&sha256sum).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert!(entry.tags.is_empty());
    } else {
        panic!("File not found after clearing tags");
    }
}