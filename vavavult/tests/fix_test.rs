// Copyright 2024 The Vavavult Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs;
use std::io::Write;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use vavavult::common::constants::{META_FILE_ADD_TIME, META_FILE_UPDATE_TIME};
use vavavult::common::metadata::MetadataEntry;
use vavavult::file::VaultPath;
use vavavult::vault::{FixError, QueryResult};

mod common;

#[test]
fn test_fix_lost_file_success() {
    // 1. Arrange: Create a vault, add a file, add a tag, and add custom metadata.
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = common::setup_encrypted_vault(&dir);
    let content = b"This is the content of the original file.";

    let mut source_file = tempfile::NamedTempFile::new().unwrap();
    source_file.write_all(content).unwrap();
    let source_path = source_file.path();

    let dest_path = VaultPath::from("/test/original.txt");
    let old_hash = vault.add_file(source_path, &dest_path).unwrap();
    vault.add_tag(&old_hash, "test-tag").unwrap();
    vault
        .set_file_metadata(
            &old_hash,
            MetadataEntry {
                key: "custom_key".to_string(),
                value: "custom_value".to_string(),
            },
        )
        .unwrap();

    let old_entry = match vault.find_by_hash(&old_hash).unwrap() {
        QueryResult::Found(entry) => entry,
        _ => panic!("File should exist"),
    };
    assert_eq!(old_entry.tags, vec!["test-tag"]);
    let old_add_time = old_entry
        .metadata
        .iter()
        .find(|m| m.key == META_FILE_ADD_TIME)
        .unwrap()
        .value
        .clone();
    let old_update_time = old_entry
        .metadata
        .iter()
        .find(|m| m.key == META_FILE_UPDATE_TIME)
        .unwrap()
        .value
        .clone();
    assert_eq!(
        old_entry
            .metadata
            .iter()
            .find(|m| m.key == "custom_key")
            .unwrap()
            .value,
        "custom_value"
    );

    // 2. Act: Simulate a lost file by deleting it from the data store.
    let data_file_path = vault.root_path.join("data").join(old_hash.to_string());
    assert!(data_file_path.exists());
    fs::remove_file(&data_file_path).unwrap();
    assert!(!data_file_path.exists());

    // Introduce a delay to ensure timestamps will be different.
    thread::sleep(Duration::from_millis(2));

    // Call fix_file with the correct original file.
    let fix_result = vault.fix_file(source_path, &dest_path);
    assert!(fix_result.is_ok());
    let new_hash = fix_result.unwrap();

    // 3. Assert: Verify the fix was successful.
    assert_ne!(old_hash, new_hash);

    // a. Old data file should still be gone.
    assert!(!data_file_path.exists());

    // b. New data file should exist.
    let new_data_file_path = vault.root_path.join("data").join(new_hash.to_string());
    assert!(new_data_file_path.exists());

    // c. The file should be accessible at the same path with the new hash.
    let new_entry = match vault.find_by_path(&dest_path).unwrap() {
        QueryResult::Found(entry) => entry,
        _ => panic!("File should be found at original path"),
    };
    assert_eq!(new_entry.sha256sum, new_hash);
    assert_eq!(new_entry.original_sha256sum, old_entry.original_sha256sum);

    // d. Tags should have been preserved.
    assert_eq!(new_entry.tags, vec!["test-tag"]);

    // e. Custom metadata should have been preserved.
    assert_eq!(
        new_entry
            .metadata
            .iter()
            .find(|m| m.key == "custom_key")
            .unwrap()
            .value,
        "custom_value"
    );

    // f. Timestamps should be correctly handled.
    let new_add_time = new_entry
        .metadata
        .iter()
        .find(|m| m.key == META_FILE_ADD_TIME)
        .unwrap()
        .value
        .clone();
    let new_update_time = new_entry
        .metadata
        .iter()
        .find(|m| m.key == META_FILE_UPDATE_TIME)
        .unwrap()
        .value
        .clone();
    assert_eq!(new_add_time, old_add_time);
    assert!(new_update_time > old_update_time);

    // g. Extracted content should be correct.
    let extracted_file_path = vault_path.join("extracted.txt");
    vault.extract_file(&new_hash, &extracted_file_path).unwrap();
    let extracted_content = fs::read(&extracted_file_path).unwrap();
    assert_eq!(extracted_content, content);
}
#[test]
fn test_fix_file_hash_mismatch() {
    // 1. Arrange: Create a vault and add a file.
    let dir = tempdir().unwrap();
    let (_, mut vault) = common::setup_encrypted_vault(&dir);

    // Add original file
    let mut original_file = tempfile::NamedTempFile::new().unwrap();
    original_file.write_all(b"original content").unwrap();
    let vault_path = VaultPath::from("/file.txt");
    vault.add_file(original_file.path(), &vault_path).unwrap();

    // Create an "imposter" file with different content.
    let mut imposter_file = tempfile::NamedTempFile::new().unwrap();
    imposter_file.write_all(b"imposter content").unwrap();

    // 2. Act: Attempt to "fix" the file using the imposter file.
    let fix_result = vault.fix_file(imposter_file.path(), &vault_path);

    // 3. Assert: The operation should fail with a HashMismatch error.
    assert!(matches!(fix_result, Err(FixError::HashMismatch)));
}

#[test]
fn test_fix_file_not_found_in_db() {
    // 1. Arrange: Create a vault and a source file.
    let dir = tempdir().unwrap();
    let (_, mut vault) = common::setup_encrypted_vault(&dir);
    let mut source_file = tempfile::NamedTempFile::new().unwrap();
    source_file.write_all(b"some content").unwrap();

    // 2. Act: Attempt to fix a file at a path that doesn't exist in the vault.
    let non_existent_path = VaultPath::from("/non/existent.txt");
    let fix_result = vault.fix_file(source_file.path(), &non_existent_path);

    // 3. Assert: The operation should fail with a NotFound error.
    assert!(matches!(fix_result, Err(FixError::NotFound(_))));
}
