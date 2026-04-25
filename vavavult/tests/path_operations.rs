use tempfile::tempdir;
use vavavult::file::VaultPath;
use vavavult::vault::{ListPathEntry, PathOperationError, QueryPathResult};

mod common;
use common::{create_dummy_file, setup_encrypted_vault};

#[test]
fn test_copy_file_path_reuses_content_and_copies_tags() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let source_file = create_dummy_file(&dir, "source.txt", "shared payload");
    let source_path = VaultPath::from("/docs/source.txt");
    let target_path = VaultPath::from("/copies/source-copy.txt");

    let hash = vault.add_file(&source_file, &source_path, None).unwrap();
    vault.add_tag(&source_path, "tag-a").unwrap();
    vault.add_tag(&source_path, "tag-b").unwrap();

    vault.copy_file_path(&source_path, &target_path).unwrap();

    let copied_entry = match vault.find_by_path(&target_path).unwrap() {
        QueryPathResult::Found(entry) => entry,
        QueryPathResult::NotFound => panic!("copied path not found"),
    };
    assert_eq!(copied_entry.sha256sum, hash);
    assert_eq!(
        copied_entry.tags,
        vec!["tag-a".to_string(), "tag-b".to_string()]
    );
    assert_eq!(vault.get_file_count().unwrap(), 2);
    assert_eq!(vault.get_storage_file_count().unwrap(), 1);
}

#[test]
fn test_create_path_from_hash_reuses_content_without_tags() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let source_file = create_dummy_file(&dir, "source.txt", "hash linked payload");
    let source_path = VaultPath::from("/source.txt");
    let target_path = VaultPath::from("/linked/by-hash.txt");

    let hash = vault.add_file(&source_file, &source_path, None).unwrap();
    vault.add_tag(&source_path, "source-only").unwrap();

    vault.create_path_from_hash(&hash, &target_path).unwrap();

    let linked_entry = match vault.find_by_path(&target_path).unwrap() {
        QueryPathResult::Found(entry) => entry,
        QueryPathResult::NotFound => panic!("linked path not found"),
    };
    assert_eq!(linked_entry.sha256sum, hash);
    assert!(linked_entry.tags.is_empty());
    assert_eq!(vault.list_paths_by_hash(&hash).unwrap().len(), 2);
    assert_eq!(vault.get_storage_file_count().unwrap(), 1);
}

#[test]
fn test_create_empty_path_creates_directory_tree() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let empty_path = VaultPath::from("/empty/nested/");

    vault.create_empty_path(&empty_path).unwrap();

    let root_entries = vault.list_by_path(&VaultPath::from("/")).unwrap();
    assert!(root_entries.iter().any(|entry| matches!(
        entry,
        ListPathEntry::Directory(directory) if directory.path == VaultPath::from("/empty/")
    )));

    let nested_entries = vault.list_by_path(&VaultPath::from("/empty/")).unwrap();
    assert!(nested_entries.iter().any(|entry| matches!(
        entry,
        ListPathEntry::Directory(directory) if directory.path == empty_path
    )));
    assert!(vault.list_by_path(&empty_path).unwrap().is_empty());
}

#[test]
fn test_path_creation_rejects_conflicts() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let source_file = create_dummy_file(&dir, "source.txt", "conflict payload");
    let source_path = VaultPath::from("/source.txt");
    let hash = vault.add_file(&source_file, &source_path, None).unwrap();

    assert!(matches!(
        vault
            .create_path_from_hash(&hash, &source_path)
            .unwrap_err(),
        PathOperationError::TargetPathExists(_)
    ));
    assert!(matches!(
        vault
            .create_empty_path(&VaultPath::from("/source.txt/"))
            .unwrap_err(),
        PathOperationError::TargetPathExists(_)
    ));
    assert!(matches!(
        vault
            .copy_file_path(
                &VaultPath::from("/missing.txt"),
                &VaultPath::from("/copy.txt")
            )
            .unwrap_err(),
        PathOperationError::SourcePathNotFound(_)
    ));
}
