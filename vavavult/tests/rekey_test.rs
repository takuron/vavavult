use std::fs;
use std::io::Write;
use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::{
    ListPathEntry, OpenError, QueryFileResult, QueryPathResult, UpdateError, Vault,
};

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
    let old_hash = vault.add_file(source_path, &dest_path, None).unwrap();

    // 从数据库中获取完整的 FileEntry
    let old_entry = match vault.find_by_hash(&old_hash).unwrap() {
        QueryFileResult::Found(entry) => entry,
        QueryFileResult::NotFound => panic!("File should have been added"),
    };

    // 2. Act: 执行密钥轮换
    let pending_rekey_tasks = vault.prepare_rekey_tasks(&[old_hash.clone()]).unwrap();
    let rekey_task = Vault::rekey_task(
        vault.storage.as_ref(),
        pending_rekey_tasks.into_iter().next().unwrap(),
    )
    .unwrap();
    let new_hash = rekey_task.new_file_entry.sha256sum.clone();

    // 确认新旧哈希不同
    assert_ne!(old_hash, new_hash);

    vault.commit_rekey_tasks(vec![rekey_task]).unwrap();

    // 3. Assert: 验证轮换结果

    // a. 使用旧哈希查询应该失败
    assert!(matches!(
        vault.find_by_hash(&old_hash).unwrap(),
        QueryFileResult::NotFound
    ));

    // b. 使用新哈希查询应该成功
    let new_entry = match vault.find_by_hash(&new_hash).unwrap() {
        QueryFileResult::Found(entry) => entry,
        QueryFileResult::NotFound => panic!("File should be found with new hash"),
    };

    // c. 验证新条目的元数据是否正确
    assert_eq!(new_entry.sha256sum, new_hash);
    assert_eq!(
        vault.list_paths_by_hash(&new_hash).unwrap(),
        vec![dest_path]
    );
    assert_eq!(new_entry.original_sha256sum, old_entry.original_sha256sum);
    assert_ne!(new_entry.encrypt_password, old_entry.encrypt_password);

    // d. 提取文件并验证内容
    let extracted_file_path = vault_path.join("extracted.txt");
    vault.extract_file(&new_hash, &extracted_file_path).unwrap();

    let extracted_content = fs::read(&extracted_file_path).unwrap();
    assert_eq!(extracted_content, content);
}

#[test]
fn test_rekey_preserves_referenced_paths_directories_and_tags() {
    // 1. Arrange: 创建一个文件，并为同一内容建立多条路径引用。
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let content = b"shared content referenced by multiple vault paths";

    let mut source_file = tempfile::NamedTempFile::new().unwrap();
    source_file.write_all(content).unwrap();

    let source_path = VaultPath::from("/docs/source.txt");
    let copied_path = VaultPath::from("/copies/source-copy.txt");
    let linked_path = VaultPath::from("/deep/nested/source-linked.txt");

    let old_hash = vault
        .add_file(source_file.path(), &source_path, None)
        .unwrap();
    vault.add_tag(&source_path, "source-tag").unwrap();
    vault.copy_file_path(&source_path, &copied_path).unwrap();
    vault.add_tag(&copied_path, "copy-tag").unwrap();
    vault
        .create_path_from_hash(&old_hash, &linked_path)
        .unwrap();
    vault.add_tag(&linked_path, "linked-tag").unwrap();

    let old_entry = match vault.find_by_hash(&old_hash).unwrap() {
        QueryFileResult::Found(entry) => entry,
        QueryFileResult::NotFound => panic!("File should have been added"),
    };

    // 2. Act: 对共享内容执行 rekey。
    let pending_rekey_tasks = vault.prepare_rekey_tasks(&[old_hash.clone()]).unwrap();
    let rekey_task = Vault::rekey_task(
        vault.storage.as_ref(),
        pending_rekey_tasks.into_iter().next().unwrap(),
    )
    .unwrap();
    let new_hash = rekey_task.new_file_entry.sha256sum.clone();

    assert_ne!(old_hash, new_hash);

    vault.commit_rekey_tasks(vec![rekey_task]).unwrap();

    // 3. Assert: 旧哈希消失，新哈希继承所有路径引用。
    assert!(matches!(
        vault.find_by_hash(&old_hash).unwrap(),
        QueryFileResult::NotFound
    ));

    let new_entry = match vault.find_by_hash(&new_hash).unwrap() {
        QueryFileResult::Found(entry) => entry,
        QueryFileResult::NotFound => panic!("File should be found with new hash"),
    };
    assert_eq!(new_entry.original_sha256sum, old_entry.original_sha256sum);
    assert_ne!(new_entry.encrypt_password, old_entry.encrypt_password);

    let mut actual_paths = vault
        .list_paths_by_hash(&new_hash)
        .unwrap()
        .into_iter()
        .map(|path| path.to_string())
        .collect::<Vec<_>>();
    actual_paths.sort();
    let mut expected_paths = vec![
        source_path.to_string(),
        copied_path.to_string(),
        linked_path.to_string(),
    ];
    expected_paths.sort();
    assert_eq!(actual_paths, expected_paths);

    assert_path_tags(&vault, &source_path, &new_hash, &["source-tag"]);
    assert_path_tags(&vault, &copied_path, &new_hash, &["copy-tag", "source-tag"]);
    assert_path_tags(&vault, &linked_path, &new_hash, &["linked-tag"]);

    let deep_entries = vault
        .list_by_path(&VaultPath::from("/deep/nested/"))
        .unwrap();
    assert!(deep_entries.iter().any(|entry| matches!(
        entry,
        ListPathEntry::File(file_entry) if file_entry.path == linked_path && file_entry.sha256sum == new_hash
    )));

    let extracted_file_path = vault_path.join("extracted-shared.txt");
    vault.extract_file(&new_hash, &extracted_file_path).unwrap();
    assert_eq!(fs::read(extracted_file_path).unwrap(), content);
}

fn assert_path_tags(
    vault: &Vault,
    path: &VaultPath,
    expected_hash: &vavavult::common::hash::VaultHash,
    expected_tags: &[&str],
) {
    let entry = match vault.find_by_path(path).unwrap() {
        QueryPathResult::Found(entry) => entry,
        QueryPathResult::NotFound => panic!("Path should exist after rekey: {}", path),
    };

    assert_eq!(&entry.sha256sum, expected_hash);

    let mut actual_tags = entry.tags;
    actual_tags.sort();
    let mut expected_tags = expected_tags
        .iter()
        .map(|tag| tag.to_string())
        .collect::<Vec<_>>();
    expected_tags.sort();
    assert_eq!(actual_tags, expected_tags);
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

    let file_hash = vault.add_file(source_path, &dest_path, None).unwrap();
    // Drop the vault to release the file lock
    drop(vault);

    // 2. Act: 更新密码
    let result = Vault::update_password(&vault_path, "password123", "new_password_456");
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
        QueryFileResult::Found(entry) => entry,
        QueryFileResult::NotFound => panic!("File should still exist after password update"),
    };
    assert_eq!(entry_after_update.sha256sum, file_hash);
    assert_eq!(
        vault_after_update.list_paths_by_hash(&file_hash).unwrap(),
        vec![VaultPath::from("/secret.txt")]
    );

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
        Vault::update_password(&vault_path, "wrong_old_password", "another_password");
    assert!(matches!(
        update_with_wrong_pass,
        Err(UpdateError::InvalidOldPassword)
    ));
}
