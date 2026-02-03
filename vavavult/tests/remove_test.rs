use std::fs;
use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::QueryResult;

mod common;

#[test]
fn test_force_remove_idempotency() {
    // 1. Setup: create a vault and add a file
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let file_path = common::create_dummy_file(&dir, "test_file.txt", "some content");

    let original_hash = vault
        .add_file(&file_path, &VaultPath::try_from("/test_file.txt").unwrap())
        .unwrap();

    // 2. First removal should succeed
    assert!(
        vault.force_remove_file(&original_hash).is_ok(),
        "First force_remove_file should succeed"
    );

    // 3. Check that the file is gone from the database and storage
    let query_result = vault.find_by_hash(&original_hash).unwrap();
    assert!(
        matches!(query_result, QueryResult::NotFound),
        "File should be not found in DB after force remove"
    );
    let data_dir = vault_path.join("data");
    let physical_path = data_dir.join(original_hash.to_string());
    assert!(
        !physical_path.exists(),
        "File should not exist in storage after force remove"
    );

    // 4. Second removal on the same hash should also succeed (idempotency)
    assert!(
        vault.force_remove_file(&original_hash).is_ok(),
        "Second force_remove_file on the same hash should also succeed"
    );
}

#[test]
fn test_force_remove_with_missing_physical_file() {
    // 1. Setup: create a vault and add a file
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let file_path = common::create_dummy_file(&dir, "test_file.txt", "some content");
    let hash = vault
        .add_file(&file_path, &VaultPath::try_from("/test_file.txt").unwrap())
        .unwrap();

    // 2. Manually delete the physical file from storage
    let physical_path = vault_path.join("data").join(hash.to_string());
    fs::remove_file(physical_path).unwrap();

    // 3. `force_remove_file` should still succeed
    assert!(
        vault.force_remove_file(&hash).is_ok(),
        "force_remove_file should succeed even if physical file is already gone"
    );

    // 4. Check that the file is gone from the database
    let query_result = vault.find_by_hash(&hash).unwrap();
    assert!(
        matches!(query_result, QueryResult::NotFound),
        "File should be not found in DB after force remove"
    );
}

#[test]
fn test_force_remove_with_missing_db_record() {
    // 1. Setup: create a vault and add a file
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let file_path = common::create_dummy_file(&dir, "test_file.txt", "some content");
    let hash = vault
        .add_file(&file_path, &VaultPath::try_from("/test_file.txt").unwrap())
        .unwrap();

    // 2. Manually delete the record from the database
    vault
        .database_connection
        .execute("DELETE FROM files WHERE sha256sum = ?1", [&hash])
        .unwrap();

    // Pre-check: ensure physical file still exists
    let physical_path = vault_path.join("data").join(hash.to_string());
    assert!(
        physical_path.exists(),
        "Physical file should exist before force remove"
    );

    // 3. `force_remove_file` should still succeed
    assert!(
        vault.force_remove_file(&hash).is_ok(),
        "force_remove_file should succeed even if DB record is already gone"
    );

    // 4. Check that the physical file is now also gone
    assert!(
        !physical_path.exists(),
        "Physical file should be removed by force_remove_file"
    );
}
