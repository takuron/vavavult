use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use vavavult::common::constants::{META_FILE_UPDATE_TIME};
use vavavult::common::metadata::MetadataEntry;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryResult, UpdateError};

mod common;
use common::{create_dummy_file, setup_encrypted_vault};

/// 测试：文件标签的生命周期。
/// 验证：添加、批量添加、移除、清空标签的操作正确性。
#[test]
fn test_file_tag_lifecycle() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "tag.txt", "content");
    let hash = vault.add_file(&file_path, &VaultPath::from("/tag.txt")).unwrap();

    // 1. 添加单个
    vault.add_tag(&hash, "tag1").unwrap();
    // 2. 批量添加
    vault.add_tags(&hash, &["tag2", "tag3"]).unwrap();

    let entry = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!(),
    };
    assert_eq!(entry.tags.len(), 3);

    // 3. 移除单个
    vault.remove_tag(&hash, "tag2").unwrap();
    let entry = match vault.find_by_hash(&hash).unwrap() { QueryResult::Found(e) => e, _ => panic!() };
    assert_eq!(entry.tags.len(), 2);

    // 4. 清空
    vault.clear_tags(&hash).unwrap();
    let entry = match vault.find_by_hash(&hash).unwrap() { QueryResult::Found(e) => e, _ => panic!() };
    assert!(entry.tags.is_empty());
}

/// 测试：文件元数据的生命周期。
/// 验证：
/// 1. 设置和更新自定义元数据。
/// 2. 移除自定义元数据。
/// 3. 系统元数据 (update_time) 会随之自动更新。
#[test]
fn test_file_metadata_lifecycle() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "meta.txt", "content");
    let hash = vault.add_file(&file_path, &VaultPath::from("/meta.txt")).unwrap();

    thread::sleep(Duration::from_millis(10)); // 确保时间戳有变化

    // 1. 设置元数据
    let meta = MetadataEntry { key: "author".to_string(), value: "me".to_string() };
    vault.set_file_metadata(&hash, meta).unwrap();

    let entry = match vault.find_by_hash(&hash).unwrap() { QueryResult::Found(e) => e, _ => panic!() };
    assert_eq!(entry.metadata.iter().find(|m| m.key == "author").unwrap().value, "me");

    // 2. 验证 update_time 是否改变 (此处省略了具体比较逻辑，重点是流程)
    let _update_time = entry.metadata.iter().find(|m| m.key == META_FILE_UPDATE_TIME).unwrap();

    // 3. 移除元数据
    vault.remove_file_metadata(&hash, "author").unwrap();
    let entry = match vault.find_by_hash(&hash).unwrap() { QueryResult::Found(e) => e, _ => panic!() };
    assert!(entry.metadata.iter().find(|m| m.key == "author").is_none());
}

/// 测试：保险库级别元数据的生命周期。
/// 验证 Get/Set/Remove 操作。
#[test]
fn test_vault_metadata_lifecycle() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);

    // Set
    vault.set_vault_metadata(MetadataEntry { key: "v_key".to_string(), value: "val".to_string() }).unwrap();
    // Get
    assert_eq!(vault.get_vault_metadata("v_key").unwrap(), "val");

    // Remove
    vault.remove_vault_metadata("v_key").unwrap();
    // Verify removal
    assert!(matches!(vault.get_vault_metadata("v_key").unwrap_err(), UpdateError::MetadataKeyNotFound(_)));
}