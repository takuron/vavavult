use std::fs;

use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::{ListPathEntry, QueryFileResult, QueryPathResult};

mod common;

#[test]
fn test_metadata_operations_survive_missing_storage_file() {
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let source_path = common::create_dummy_file(&dir, "missing.txt", "metadata survives");
    let vault_path_entry = VaultPath::from("/docs/missing.txt");
    let moved_path = VaultPath::from("/archive/missing.txt");

    let hash = vault
        .add_file(&source_path, &vault_path_entry, None)
        .unwrap();
    vault.add_tag(&vault_path_entry, "lost-storage").unwrap();

    fs::remove_file(vault_path.join("data").join(hash.to_string())).unwrap();

    assert!(matches!(
        vault.find_by_hash(&hash).unwrap(),
        QueryFileResult::Found(_)
    ));
    assert!(matches!(
        vault.find_by_path(&vault_path_entry).unwrap(),
        QueryPathResult::Found(_)
    ));
    assert_eq!(vault.find_by_tag("lost-storage").unwrap().len(), 1);
    assert_eq!(vault.find_by_keyword("missing").unwrap().len(), 1);

    let listed = vault.list_by_path(&VaultPath::from("/docs/")).unwrap();
    assert!(listed.iter().any(|entry| matches!(
        entry,
        ListPathEntry::File(file) if file.path == vault_path_entry
    )));

    vault.move_path(&vault_path_entry, &moved_path).unwrap();
    assert!(matches!(
        vault.find_by_path(&moved_path).unwrap(),
        QueryPathResult::Found(_)
    ));

    assert!(
        vault
            .extract_file(&hash, &dir.path().join("out.txt"))
            .is_err()
    );
    assert!(vault.verify_file_integrity(&hash).is_err());

    let pending = vault.prepare_rekey_tasks(&[hash.clone()]).unwrap();
    assert!(
        vavavult::vault::Vault::rekey_task(vault.storage.as_ref(), pending[0].clone()).is_err()
    );

    vault.remove_file_by_path(&moved_path).unwrap();
    assert!(matches!(
        vault.find_by_hash(&hash).unwrap(),
        QueryFileResult::NotFound
    ));
}

#[test]
fn test_hash_remove_survives_missing_storage_file() {
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let source_path = common::create_dummy_file(&dir, "hash-remove.txt", "remove missing");
    let hash = vault
        .add_file(&source_path, &VaultPath::from("/hash-remove.txt"), None)
        .unwrap();

    fs::remove_file(vault_path.join("data").join(hash.to_string())).unwrap();

    vault.remove_file(&hash).unwrap();
    assert!(matches!(
        vault.find_by_hash(&hash).unwrap(),
        QueryFileResult::NotFound
    ));
}
