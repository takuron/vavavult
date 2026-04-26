use std::fs;
use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::QueryFileResult;

mod common;

#[test]
fn test_remove_by_hash_deletes_database_and_storage() {
    // 1. Setup: create a vault and add a file
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let file_path = common::create_dummy_file(&dir, "test_file.txt", "some content");

    let original_hash = vault
        .add_file(
            &file_path,
            &VaultPath::try_from("/test_file.txt").unwrap(),
            None,
        )
        .unwrap();

    // 2. Removal should succeed
    assert!(vault.remove_file(&original_hash).is_ok());

    // 3. Check that the file is gone from the database and storage
    let query_result = vault.find_by_hash(&original_hash).unwrap();
    assert!(
        matches!(query_result, QueryFileResult::NotFound),
        "File should be not found in DB after remove"
    );
    let data_dir = vault_path.join("data");
    let physical_path = data_dir.join(original_hash.to_string());
    assert!(
        !physical_path.exists(),
        "File should not exist in storage after remove"
    );
}

#[test]
fn test_remove_by_hash_with_missing_physical_file() {
    // 1. Setup: create a vault and add a file
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let file_path = common::create_dummy_file(&dir, "test_file.txt", "some content");
    let hash = vault
        .add_file(
            &file_path,
            &VaultPath::try_from("/test_file.txt").unwrap(),
            None,
        )
        .unwrap();

    // 2. Manually delete the physical file from storage
    let physical_path = vault_path.join("data").join(hash.to_string());
    fs::remove_file(physical_path).unwrap();

    // 3. `remove_file` should still succeed
    assert!(vault.remove_file(&hash).is_ok());

    // 4. Check that the file is gone from the database
    let query_result = vault.find_by_hash(&hash).unwrap();
    assert!(
        matches!(query_result, QueryFileResult::NotFound),
        "File should be not found in DB after remove"
    );
}
