use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use sha2::{Digest, Sha512};
use tempfile::{tempdir, TempDir};
use vavavult::common::constants::{
    CURRENT_VAULT_VERSION, DATA_SUBDIR, META_FILE_ADD_TIME, META_FILE_SIZE,
    META_FILE_UPDATE_TIME, META_SOURCE_MODIFIED_TIME, META_VAULT_CREATE_TIME,
    META_VAULT_UPDATE_TIME,
};
use vavavult::common::hash::VaultHash;
use vavavult::common::metadata::MetadataEntry;
use vavavult::file::encrypt::verify_v2_encrypt_check;
use vavavult::file::VaultPath;
use vavavult::vault::{
    AddFileError, CreateError, OpenError, QueryError, QueryResult, UpdateError, Vault,
};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
// 导入新的 API 函数和类型
use vavavult::vault::{
    encrypt_file_for_add_standalone, execute_extraction_task_standalone, ExtractionTask,
};
use vavavult::vault::DirectoryEntry;

// ---  V2 文件库测试 ---

/// 测试成功创建一个新的、非加密的 V2 保险库
#[test]
fn test_v2_create_non_encrypted_vault_success() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("v2-non-encrypted");
    let vault_name = "my-v2-test-vault";

    // 2. 执行创建
    let result = Vault::create_vault(&vault_path, vault_name, None);
    assert!(result.is_ok(), "Vault creation should succeed");
    let vault = result.unwrap();

    // 3. 验证 VaultConfig (V2 特性)
    assert_eq!(vault.config.name, vault_name);
    assert_eq!(
        vault.config.version, CURRENT_VAULT_VERSION,
        "Version should be V2"
    ); //
    assert_eq!(vault.config.encrypted, false, "Should not be encrypted");
    assert!(
        vault.config.encrypt_check.is_empty(),
        "Encrypt check should be empty for non-encrypted"
    ); //

    // 4. 验证文件系统
    assert!(vault_path.join("master.json").exists());
    assert!(vault_path.join("master.db").exists());

    // 5. 验证数据库 (V2 特性：vault_metadata 表)
    let create_time: String = vault
        .database_connection
        .query_row(
            "SELECT meta_value FROM vault_metadata WHERE meta_key = ?1",
            [META_VAULT_CREATE_TIME],
            |row| row.get(0), // 编译器现在推断 T=String
        )
        .expect("Failed to query create_time");

    let update_time: String = vault
        .database_connection
        .query_row(
            "SELECT meta_value FROM vault_metadata WHERE meta_key = ?1",
            [META_VAULT_UPDATE_TIME],
            |row| row.get(0), // 编译器现在推断 T=String
        )
        .expect("Failed to query update_time");

    assert!(
        !create_time.is_empty(),
        "Create time metadata should be set in DB"
    );
    assert_eq!(
        create_time, update_time,
        "Create and update time should be identical on creation"
    );
}

/// 测试成功创建一个新的、加密的 V2 保险库
#[test]
fn test_v2_create_encrypted_vault_success() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("v2-encrypted");
    let vault_name = "my-v2-secure-vault";
    let password = "v2-password-!@#";

    // 2. 执行创建
    let result = Vault::create_vault(&vault_path, vault_name, Some(password));
    assert!(result.is_ok(), "Encrypted vault creation should succeed");
    let vault = result.unwrap();

    // 3. 验证 VaultConfig (V2 特性)
    assert_eq!(vault.config.name, vault_name);
    assert_eq!(vault.config.version, CURRENT_VAULT_VERSION); //
    assert_eq!(vault.config.encrypted, true, "Should be encrypted");

    // 验证加密检查字符串
    assert!(
        !vault.config.encrypt_check.is_empty(),
        "Encrypt check should NOT be empty"
    ); //
    assert!(
        verify_v2_encrypt_check(&vault.config.encrypt_check, password), //
        "Password should correctly verify the encrypt_check string"
    );
    assert!(
        !verify_v2_encrypt_check(&vault.config.encrypt_check, "wrong-password"),
        "Wrong password should fail verification"
    );

    // 4. 验证数据库 (V2 特性：确保 SQLCipher 已激活)
    // 尝试查询数据，如果密码错误或未设置，这里会失败
    let table_count: i64 = vault
        .database_connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='vault_metadata'",
            [],
            |row| row.get(0),
        )
        .expect("Database query should succeed with correct password");

    assert_eq!(table_count, 1, "Should be able to query encrypted DB");
}

/// 测试在已存在的目录中创建保险库应失败
#[test]
fn test_v2_create_vault_already_exists_error() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("existing-dir");
    fs::create_dir_all(&vault_path).unwrap();
    // 创建一个文件，使目录非空
    fs::write(vault_path.join("dummy.txt"), "content").unwrap();

    // 2. 执行创建
    let result = Vault::create_vault(&vault_path, "test", None);

    // 3. 验证错误
    assert!(result.is_err(), "Creation in non-empty dir should fail");
    assert!(
        matches!(result.unwrap_err(), CreateError::VaultAlreadyExists(_)), //
        "Error should be VaultAlreadyExists"
    );
}

/// 测试保险库的打开和重新打开 (非加密)
#[test]
fn test_v2_open_and_reopen_vault_cycle() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("persistent-vault");
    let vault_name = "persist-test";

    // 2. 创建并关闭
    {
        let vault = Vault::create_vault(&vault_path, vault_name, None).unwrap();
        assert_eq!(vault.config.name, vault_name);
    } // vault 在此被 drop, 连接关闭

    // 3. 重新打开
    let reopen_result = Vault::open_vault(&vault_path, None);
    assert!(reopen_result.is_ok(), "Reopening vault should succeed");
    let reopened_vault = reopen_result.unwrap();

    // 4. 验证
    assert_eq!(reopened_vault.config.name, vault_name);
    assert_eq!(reopened_vault.config.version, CURRENT_VAULT_VERSION);
    assert_eq!(reopened_vault.config.encrypted, false);
}

/// 测试加密保险库的访问控制 (打开)
#[test]
fn test_v2_open_encrypted_vault_access_control() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("secure-vault");
    let password = "v2-super-secret";
    {
        Vault::create_vault(&vault_path, "access-control", Some(password)).unwrap();
    } // 关闭保险库

    // 2. 失败：尝试不带密码打开
    let no_pass_result = Vault::open_vault(&vault_path, None);
    assert!(
        matches!(
            no_pass_result.unwrap_err(),
            OpenError::PasswordRequired
        ),
        "Should fail with PasswordRequired"
    ); //

    // 3. 失败：尝试用错误密码打开
    let wrong_pass_result = Vault::open_vault(&vault_path, Some("wrong-password"));
    assert!(
        matches!(
            wrong_pass_result.unwrap_err(),
            OpenError::InvalidPassword
        ),
        "Should fail with InvalidPassword"
    ); //

    // 4. 成功：尝试用正确密码打开
    let correct_pass_result = Vault::open_vault(&vault_path, Some(password));
    assert!(
        correct_pass_result.is_ok(),
        "Should succeed with correct password"
    );
    let vault = correct_pass_result.unwrap();
    assert_eq!(vault.config.name, "access-control");
}

/// 测试打开一个不存在的路径
#[test]
fn test_v2_open_nonexistent_vault() {
    let dir = tempdir().unwrap();
    let non_existent_path = dir.path().join("non-existent-vault");

    let result = Vault::open_vault(&non_existent_path, None);
    assert!(
        matches!(result.unwrap_err(), OpenError::PathNotFound(_)),
        "Should fail with PathNotFound"
    ); //
}

// ---  V2 文件操作测试 (add, extract, move, remove) ---

/// 辅助：创建一个带密码的 V2 保险库
fn setup_encrypted_vault(dir: &TempDir) -> (PathBuf, Vault) {
    let vault_path = dir.path().join("test-vault");
    let vault = Vault::create_vault(&vault_path, "test-vault", Some("v2-password")).unwrap();
    (vault_path, vault)
}

/// 辅助：在临时目录中创建一个虚拟文件
fn create_dummy_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let file_path = dir.path().join(name);
    let mut file = fs::File::create(&file_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file_path
}

/// 测试核心的 添加-查询-提取 循环
#[test]
fn test_v2_add_file_and_extract_file_cycle() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let dummy_file_path = create_dummy_file(&dir, "hello.txt", "Hello V2 Integrity Check");

    // 2. 添加 (Act)
    let dest_path = VaultPath::from("/docs/hello.txt");
    let add_result = vault.add_file(&dummy_file_path, &dest_path);
    assert!(add_result.is_ok(), "add_file should succeed");
    let encrypted_hash = add_result.unwrap();

    // 3. 查询验证 (Assert Add)
    let query_res = vault.find_by_path(&dest_path).unwrap();
    let entry = match query_res {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => panic!("File not found by name after adding"),
    };

    // [修改] 比较 VaultPath 和 VaultPath
    assert_eq!(entry.path, VaultPath::from("/docs/hello.txt"));

    assert_eq!(entry.sha256sum, encrypted_hash);
    assert!(!entry.original_sha256sum.to_string().is_empty()); // 确保原始哈希存在
    assert_eq!(entry.metadata.len(), 4); // 4 个系统元数据

    // 4. 提取 (Act)
    let extract_path = dir.path().join("extracted_hello.txt");
    let extract_result = vault.extract_file(&encrypted_hash, &extract_path);
    assert!(extract_result.is_ok(), "extract_file should succeed");

    // 5. 验证提取 (Assert Extract)
    assert!(extract_path.exists(), "Extracted file should exist");
    let extracted_content = fs::read_to_string(&extract_path).unwrap();
    assert_eq!(
        extracted_content, "Hello V2 Integrity Check",
        "Extracted content must match original"
    );

    // 6. 测试提取完整性检查失败 (损坏文件)
    let internal_path = vault
        .root_path
        .join(DATA_SUBDIR)
        .join(encrypted_hash.to_string());
    fs::write(internal_path, "corrupted data").unwrap(); // 故意损坏保险库中的文件

    let extract_fail_result = vault.extract_file(&encrypted_hash, &extract_path);
    assert!(
        extract_fail_result.is_err(),
        "Extract should fail on corrupted data"
    );
}

/// 测试 `add_file` 的路径解析和错误处理
#[test]
fn test_v2_add_file_paths_and_errors() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file1_path = create_dummy_file(&dir, "file1.txt", "content1");
    let file2_path = create_dummy_file(&dir, "file2.txt", "content2");

    // 2. 添加 file1
    let path1 = VaultPath::from("/file1.txt");
    vault.add_file(&file1_path, &path1).unwrap();

    // 3. 错误：添加 file2 到相同的路径
    let res_dup_path = vault.add_file(&file2_path, &path1);
    assert!(matches!(
        res_dup_path.unwrap_err(),
        AddFileError::DuplicateFileName(_)
    ));

    // 4. 错误：使用相同内容 (file1) 添加到不同路径
    let path2 = VaultPath::from("/file1_copy.txt");
    let res_dup_content = vault.add_file(&file1_path, &path2);
    assert!(matches!(
        res_dup_content.unwrap_err(),
        AddFileError::DuplicateOriginalContent(_, _)
    ));

    // 5. 成功：添加 file2 到一个目录
    let dir_path = VaultPath::from("/docs/");
    vault.add_file(&file2_path, &dir_path).unwrap();

    // 验证：文件应在 /docs/file2.txt
    let query_res = vault
        .find_by_path(&VaultPath::from("/docs/file2.txt"))
        .unwrap();
    assert!(matches!(query_res, QueryResult::Found(_)));

    // 6. 错误：尝试将文件添加到无效的文件路径 (e.g. 包含 '..')
    // VaultPath::new 应该已经处理了规范化，但我们测试 add_file 的目标路径检查
    let invalid_path = VaultPath::from("/a/b/../c.txt"); // 规范化为 /a/c.txt
    assert!(
        vault.add_file(&file1_path, &invalid_path).is_err(),
        "Should fail, duplicate original content"
    );

    // 7. 测试：添加文件到目录，路径应被正确解析
    let path_as_dir = VaultPath::from("/looks/like/dir/");
    let file3_path = create_dummy_file(&dir, "file3.txt", "content3");
    // add_file 内部调用 resolve_final_path，它会附加文件名
    let add_res = vault.add_file(&file3_path, &path_as_dir);
    assert!(add_res.is_ok());
    // [修改] 使用 find_by_path
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/looks/like/dir/file3.txt"))
            .unwrap(),
        QueryResult::Found(_)
    ));
}

/// 测试 `move_file` 和 `rename_file_inplace`
#[test]
fn test_v2_move_and_rename_file() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "move_me.txt", "move content");
    let blocker_path = create_dummy_file(&dir, "blocker.txt", "blocker content");

    let hash = vault
        .add_file(&file_path, &VaultPath::from("/dir1/move_me.txt"))
        .unwrap();
    let blocker_hash = vault
        .add_file(&blocker_path, &VaultPath::from("/dir2/blocker.txt"))
        .unwrap();
    assert_ne!(hash, blocker_hash);

    // 2. 测试 `rename_file_inplace` (成功)
    let rename_res = vault.rename_file_inplace(&hash, "renamed.txt");
    assert!(rename_res.is_ok());
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/dir1/move_me.txt"))
            .unwrap(),
        QueryResult::NotFound
    ));
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/dir1/renamed.txt"))
            .unwrap(),
        QueryResult::Found(_)
    ));

    // 3. 测试 `rename_file_inplace` (错误：无效名称)
    let rename_err = vault.rename_file_inplace(&hash, "invalid/name.txt");
    assert!(matches!(
        rename_err.unwrap_err(),
        UpdateError::InvalidFilename(_)
    ));

    // 4. 测试 `move_file` (成功：移动到目录)
    let move_to_dir_res = vault.move_file(&hash, &VaultPath::from("/dir2/"));
    assert!(move_to_dir_res.is_ok());
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/dir1/renamed.txt"))
            .unwrap(),
        QueryResult::NotFound
    ));
    // 文件应保留其名称 "renamed.txt" 并移动到 /dir2/
    let query_res = vault
        .find_by_path(&VaultPath::from("/dir2/renamed.txt"))
        .unwrap();
    match query_res {
        QueryResult::Found(entry) => assert_eq!(entry.sha256sum, hash),
        _ => panic!("File not found in new directory /dir2/"),
    }

    // 5. 测试 `move_file` (错误：路径冲突)
    let move_conflict_res = vault.move_file(&hash, &VaultPath::from("/dir2/blocker.txt"));
    assert!(matches!(
        move_conflict_res.unwrap_err(),
        UpdateError::DuplicateTargetPath(_)
    ));

    // 6. 测试 `move_file` (成功：移动并重命名)
    let move_rename_res = vault.move_file(&hash, &VaultPath::from("/final_spot.txt"));
    assert!(move_rename_res.is_ok());
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/dir2/renamed.txt"))
            .unwrap(),
        QueryResult::NotFound
    ));
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/final_spot.txt"))
            .unwrap(),
        QueryResult::Found(_)
    ));
}

/// 测试 `remove_file`
#[test]
fn test_v2_remove_file() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "delete_me.txt", "delete content");

    let hash = vault
        .add_file(&file_path, &VaultPath::from("/delete_me.txt"))
        .unwrap();

    let original_hash = match vault.find_by_hash(&hash) {
        Ok(QueryResult::Found(e)) => e.original_sha256sum,
        _ => panic!("File not found right after add"),
    };

    // 添加一些关联数据
    vault.add_tag(&hash, "temp").unwrap();
    vault
        .set_file_metadata(
            &hash,
            vavavult::common::metadata::MetadataEntry {
                key: "custom_key".to_string(),
                value: "custom_value".to_string(),
            },
        )
        .unwrap();

    // 验证物理文件存在
    let internal_path = vault
        .root_path
        .join(DATA_SUBDIR)
        .join(hash.to_string());
    assert!(internal_path.exists(), "Internal data file should exist");

    // 2. 删除 (Act)
    let remove_res = vault.remove_file(&hash);
    assert!(remove_res.is_ok());

    // 3. 验证 (Assert)
    // a. 数据库查询失败
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/delete_me.txt"))
            .unwrap(),
        QueryResult::NotFound
    ));

    assert!(matches!(
        vault.find_by_hash(&hash).unwrap(),
        QueryResult::NotFound
    ));
    // [修改] 使用 find_by_original_hash
    assert!(matches!(
        vault.find_by_original_hash(&original_hash).unwrap(),
        QueryResult::NotFound
    ));

    // b. 物理文件被删除
    assert!(
        !internal_path.exists(),
        "Internal data file should be deleted"
    );

    // c. 验证标签和元数据是否被级联删除 (通过查询空表)
    let tag_count: i64 = vault
        .database_connection
        .query_row(
            "SELECT COUNT(*) FROM tags WHERE file_sha256sum = ?1",
            [&hash],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tag_count, 0, "Tags should be cascade deleted");

    let meta_count: i64 = vault
        .database_connection
        .query_row(
            "SELECT COUNT(*) FROM metadata WHERE file_sha256sum = ?1",
            [&hash],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(meta_count, 0, "Metadata should be cascade deleted");
}

/// 测试大型二进制文件在加密保险库中的添加、提取和完整性验证。
#[test]
fn test_v2_large_file_integrity() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);

    // 文件大小和缓冲区
    const FILE_SIZE: usize = 16 * 1024 * 1024; // 32MB
    const BUFFER_SIZE: usize = 8192; // 8KB
    let mut buffer = vec![0u8; BUFFER_SIZE];

    // 2. 创建大型随机文件并计算原始 SHA512 哈希
    let source_file_path = dir.path().join("large_random_file.bin");
    let mut source_file = fs::File::create(&source_file_path).expect("Failed to create source file");
    let mut original_hasher = Sha512::new();
    let mut bytes_written = 0;

    println!("Generating 32MB random file and calculating SHA512...");
    while bytes_written < FILE_SIZE {
        let chunk_size = std::cmp::min(BUFFER_SIZE, FILE_SIZE - bytes_written);
        let chunk = &mut buffer[..chunk_size];
        openssl::rand::rand_bytes(chunk).expect("Failed to generate random bytes");
        source_file.write_all(chunk).expect("Failed to write to source file");
        original_hasher.update(chunk);
        bytes_written += chunk_size;
    }
    source_file.flush().expect("Failed to flush source file");
    let original_hash_sha512 = hex::encode(original_hasher.finalize());
    println!("Original SHA512: {}", original_hash_sha512);

    // 3. 添加文件到 Vault
    println!("Adding large file to vault...");
    let vault_dest_path = VaultPath::from("/large_files/data.bin");
    let add_result = vault.add_file(&source_file_path, &vault_dest_path);
    assert!(add_result.is_ok(), "Failed to add large file: {:?}", add_result.err());
    let file_hash_in_vault = add_result.unwrap();
    println!("File added to vault with SHA256: {}", file_hash_in_vault);

    // 4. 提取文件
    println!("Extracting large file from vault...");
    let extract_path = dir.path().join("extracted_large_file.bin");
    let extract_result = vault.extract_file(&file_hash_in_vault, &extract_path);
    assert!(extract_result.is_ok(), "Failed to extract large file: {:?}", extract_result.err());

    // 5. 计算提取后文件的 SHA512 哈希
    println!("Calculating SHA512 of extracted file...");
    let mut extracted_file = fs::File::open(&extract_path).expect("Failed to open extracted file");
    let mut extracted_hasher = Sha512::new();
    loop {
        let bytes_read = extracted_file.read(&mut buffer).expect("Failed to read extracted file");
        if bytes_read == 0 {
            break;
        }
        extracted_hasher.update(&buffer[..bytes_read]);
    }
    let extracted_hash_sha512 = hex::encode(extracted_hasher.finalize());
    println!("Extracted SHA512: {}", extracted_hash_sha512);

    // 6. [核心校验] 断言原始哈希和提取后的哈希完全一致
    assert_eq!(
        original_hash_sha512, extracted_hash_sha512,
        "SHA512 hash mismatch! Original file and extracted file differ."
    );
    println!("SHA512 hashes match. Integrity verified for 32MB file.");
}

// --- [新增] V2 搜索与列表测试 ---

/// 辅助：创建一个包含用于搜索/列表测试的数据的保险库
///
/// 结构:
/// - /file_A.txt (tags: "tag1", "common") -> hash_a
/// - /docs/file_B.md (tags: "tag2", "common") -> hash_b
/// - /docs/deep/file_C.jpg (tags: "tag3", "image") -> hash_c
/// - /another_file.txt (tags: "tag1", "unique") -> hash_d
fn setup_vault_with_search_data(
    dir: &TempDir,
) -> (Vault, VaultHash, VaultHash, VaultHash, VaultHash) {
    let (_vault_path, mut vault) = setup_encrypted_vault(dir);

    let file_a_path = create_dummy_file(dir, "file_A.txt", "content A");
    let file_b_path = create_dummy_file(dir, "file_B.md", "content B");
    let file_c_path = create_dummy_file(dir, "file_C.jpg", "content C");
    let file_d_path = create_dummy_file(dir, "another_file.txt", "content D");

    let hash_a = vault
        .add_file(&file_a_path, &VaultPath::from("/file_A.txt"))
        .unwrap();
    let hash_b = vault
        .add_file(&file_b_path, &VaultPath::from("/docs/file_B.md"))
        .unwrap();
    let hash_c = vault
        .add_file(&file_c_path, &VaultPath::from("/docs/deep/file_C.jpg"))
        .unwrap();
    let hash_d = vault
        .add_file(&file_d_path, &VaultPath::from("/another_file.txt"))
        .unwrap();

    vault.add_tag(&hash_a, "tag1").unwrap();
    vault.add_tag(&hash_a, "common").unwrap();
    vault.add_tag(&hash_b, "tag2").unwrap();
    vault.add_tag(&hash_b, "common").unwrap();
    vault.add_tag(&hash_c, "tag3").unwrap();
    vault.add_tag(&hash_c, "image").unwrap();
    vault.add_tag(&hash_d, "tag1").unwrap();
    vault.add_tag(&hash_d, "unique").unwrap();

    (vault, hash_a, hash_b, hash_c, hash_d)
}

/// 测试 `list_all`
#[test]
fn test_v2_list_all() {
    let dir = tempdir().unwrap();
    let (vault, ..) = setup_vault_with_search_data(&dir);

    let all_files = vault.list_all().unwrap();
    assert_eq!(all_files.len(), 4);
}

/// 测试 `find_by_tag`
#[test]
fn test_v2_find_by_tag() {
    let dir = tempdir().unwrap();
    let (vault, hash_a, hash_b, _hash_c, hash_d) = setup_vault_with_search_data(&dir);

    // 查找 "tag1"
    let tag1_files = vault.find_by_tag("tag1").unwrap();
    assert_eq!(tag1_files.len(), 2);
    assert!(tag1_files.iter().any(|f| f.sha256sum == hash_a));
    assert!(tag1_files.iter().any(|f| f.sha256sum == hash_d));

    // 查找 "common"
    let common_files = vault.find_by_tag("common").unwrap();
    assert_eq!(common_files.len(), 2);
    assert!(common_files.iter().any(|f| f.sha256sum == hash_a));
    assert!(common_files.iter().any(|f| f.sha256sum == hash_b));

    // 查找不存在的
    let none_files = vault.find_by_tag("nonexistent").unwrap();
    assert_eq!(none_files.len(), 0);
}

/// 测试 `find_by_keyword` (不区分大小写，搜索路径和标签)
#[test]
fn test_v2_find_by_keyword() {
    let dir = tempdir().unwrap();
    let (vault, hash_a, hash_b, hash_c, hash_d) = setup_vault_with_search_data(&dir);

    // 搜索 "file" (匹配路径)
    let file_files = vault.find_by_keyword("file").unwrap();
    assert_eq!(file_files.len(), 4);

    // 搜索 "tag1" (匹配标签)
    let tag1_files = vault.find_by_keyword("tag1").unwrap();
    assert_eq!(tag1_files.len(), 2);

    // 搜索 "docs" (匹配路径)
    let docs_files = vault.find_by_keyword("docs").unwrap();
    assert_eq!(docs_files.len(), 2);
    assert!(docs_files.iter().any(|f| f.sha256sum == hash_b));
    assert!(docs_files.iter().any(|f| f.sha256sum == hash_c));

    // 搜索 "image" (匹配标签)
    let image_files = vault.find_by_keyword("image").unwrap();
    assert_eq!(image_files.len(), 1);
    assert_eq!(image_files[0].sha256sum, hash_c);

    // 搜索 "deep" (匹配路径)
    let deep_files = vault.find_by_keyword("deep").unwrap();
    assert_eq!(deep_files.len(), 1);
    assert_eq!(deep_files[0].sha256sum, hash_c);

    // 搜索 "unique" (匹配标签)
    let unique_files = vault.find_by_keyword("unique").unwrap();
    assert_eq!(unique_files.len(), 1);
    assert_eq!(unique_files[0].sha256sum, hash_d);

    // 搜索 "A.TXT" (测试不区分大小写)
    let case_files = vault.find_by_keyword("A.TXT").unwrap();
    assert_eq!(case_files.len(), 1);
    assert_eq!(case_files[0].sha256sum, hash_a);

    // 搜索 "nonexistent"
    let none_files = vault.find_by_keyword("nonexistent").unwrap();
    assert_eq!(none_files.len(), 0);
}

/// 测试 `list_entries_by_path` 接口
#[test]
fn test_v2_list_entries_by_path() {
    let dir = tempdir().unwrap();
    let (vault, hash_a, hash_b, hash_c, hash_d) = setup_vault_with_search_data(&dir);

    // 数据结构回顾:
    // - /file_A.txt (hash_a)
    // - /another_file.txt (hash_d)
    // - /docs/file_B.md (hash_b)
    // - /docs/deep/file_C.jpg (hash_c)

    // 1. 测试根目录列表 "/"
    // 预期:
    // - File: /another_file.txt
    // - Directory: /docs/
    // - File: /file_A.txt
    let root_entries = vault.list_entries_by_path(&VaultPath::from("/")).unwrap();
    assert_eq!(root_entries.len(), 3);

    // 验证条目类型和内容
    match &root_entries[0] {
        DirectoryEntry::File(entry) => {
            assert_eq!(entry.path.as_str(), "/another_file.txt");
            assert_eq!(entry.sha256sum, hash_d);
            assert!(entry.tags.contains(&"unique".to_string())); // 验证包含完整信息
        },
        _ => panic!("Expected File entry for /another_file.txt"),
    }

    match &root_entries[1] {
        DirectoryEntry::Directory(path) => {
            assert_eq!(path.as_str(), "/docs/");
        },
        _ => panic!("Expected Directory entry for /docs/"),
    }

    match &root_entries[2] {
        DirectoryEntry::File(entry) => {
            assert_eq!(entry.path.as_str(), "/file_A.txt");
            assert_eq!(entry.sha256sum, hash_a);
        },
        _ => panic!("Expected File entry for /file_A.txt"),
    }

    // 2. 测试子目录列表 "/docs/"
    // 预期:
    // - Directory: /docs/deep/
    // - File: /docs/file_B.md
    let docs_entries = vault.list_entries_by_path(&VaultPath::from("/docs/")).unwrap();
    assert_eq!(docs_entries.len(), 2);

    match &docs_entries[0] {
        DirectoryEntry::Directory(path) => assert_eq!(path.as_str(), "/docs/deep/"),
        _ => panic!("Expected Directory entry for /docs/deep/"),
    }

    match &docs_entries[1] {
        DirectoryEntry::File(entry) => {
            assert_eq!(entry.path.as_str(), "/docs/file_B.md");
            assert_eq!(entry.sha256sum, hash_b);
        },
        _ => panic!("Expected File entry for /docs/file_B.md"),
    }

    // 3. 测试更深层目录 "/docs/deep/"
    // 预期:
    // - File: /docs/deep/file_C.jpg
    let deep_entries = vault.list_entries_by_path(&VaultPath::from("/docs/deep/")).unwrap();
    assert_eq!(deep_entries.len(), 1);
    match &deep_entries[0] {
        DirectoryEntry::File(entry) => {
            assert_eq!(entry.path.as_str(), "/docs/deep/file_C.jpg");
            assert_eq!(entry.sha256sum, hash_c);
        },
        _ => panic!("Expected File entry"),
    }

    // 4. 错误测试：尝试对文件路径调用
    let file_err = vault.list_entries_by_path(&VaultPath::from("/file_A.txt"));
    assert!(matches!(file_err, Err(QueryError::NotADirectory(_))));
}

/// 测试 `list_by_path` (返回 `Vec<VaultPath>`)
#[test]
fn test_v2_list_by_path() {
    let dir = tempdir().unwrap();
    let (vault, ..) = setup_vault_with_search_data(&dir);

    // 1. 列表 /
    let mut root_list = vault.list_by_path(&VaultPath::from("/")).unwrap();
    root_list.sort(); // 确保顺序
    assert_eq!(
        root_list,
        vec![
            VaultPath::from("/another_file.txt"),
            VaultPath::from("/docs/"), // [修正] 确保这里有斜杠
            VaultPath::from("/file_A.txt"),
        ]
    );

    // 2. 列表 /docs/
    let mut docs_list = vault.list_by_path(&VaultPath::from("/docs/")).unwrap();
    docs_list.sort();
    assert_eq!(
        docs_list,
        vec![
            VaultPath::from("/docs/deep/"),
            VaultPath::from("/docs/file_B.md"),
        ]
    );

    // 3. 列表 /docs/deep/
    let mut deep_list = vault
        .list_by_path(&VaultPath::from("/docs/deep/"))
        .unwrap();
    deep_list.sort();
    assert_eq!(
        deep_list,
        vec![VaultPath::from("/docs/deep/file_C.jpg"),]
    );

    // 4. 列表空目录 /nonexistent/
    let empty_list = vault
        .list_by_path(&VaultPath::from("/nonexistent/"))
        .unwrap();
    assert!(empty_list.is_empty());

    // 5. 错误：在文件上调用
    let file_path = VaultPath::from("/file_A.txt");
    let file_list_err = vault.list_by_path(&file_path);
    assert!(matches!(
        file_list_err,
        Err(QueryError::NotADirectory(_))
    ));
}

/// 测试 `list_all_recursive` (返回 `Vec<VaultHash>`)
#[test]
fn test_v2_list_all_recursive() {
    let dir = tempdir().unwrap();
    let (vault, hash_a, hash_b, hash_c, hash_d) = setup_vault_with_search_data(&dir);

    // 1. 递归列表 /docs/
    let mut docs_hashes = vault
        .list_all_recursive(&VaultPath::from("/docs/"))
        .unwrap();
    docs_hashes.sort();
    let mut expected_docs_hashes = vec![hash_b, hash_c];
    expected_docs_hashes.sort();
    assert_eq!(docs_hashes, expected_docs_hashes);

    // 2. 递归列表 / (全部)
    let mut all_hashes = vault
        .list_all_recursive(&VaultPath::from("/"))
        .unwrap();
    all_hashes.sort();
    let mut expected_all_hashes = vec![hash_a, hash_b, hash_c, hash_d];
    expected_all_hashes.sort();
    assert_eq!(all_hashes, expected_all_hashes);

    // 3. 错误：在文件上调用
    let file_path = VaultPath::from("/file_A.txt");
    let file_list_err = vault.list_all_recursive(&file_path);
    assert!(matches!(
        file_list_err,
        Err(QueryError::NotADirectory(_))
    ));
}

// --- [新套件] V2 元数据和标签管理 ---

/// 测试文件标签 (Tags) 的完整生命周期
#[test]
fn test_v2_file_tag_lifecycle() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "tag_file.txt", "tag content");
    let hash = vault.add_file(&file_path, &VaultPath::from("/tag_file.txt")).unwrap();

    // 2. 验证初始状态 (无标签)
    let entry = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert!(entry.tags.is_empty(), "Initial tags should be empty");

    // 3. 添加单个标签
    vault.add_tag(&hash, "tag1").unwrap();

    // 4. 批量添加标签 (测试重复)
    vault.add_tags(&hash, &["tag2", "tag1", "tag3"]).unwrap();

    // 5. 验证添加结果
    let entry = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    let mut sorted_tags = entry.tags;
    sorted_tags.sort();
    assert_eq!(sorted_tags, vec!["tag1", "tag2", "tag3"], "Tags mismatch after add_tags");

    // 6. 移除单个标签
    vault.remove_tag(&hash, "tag2").unwrap();
    let entry = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    let mut sorted_tags = entry.tags;
    sorted_tags.sort();
    assert_eq!(sorted_tags, vec!["tag1", "tag3"], "Tags mismatch after remove_tag");

    // 7. 清除所有标签
    vault.clear_tags(&hash).unwrap();
    let entry = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert!(entry.tags.is_empty(), "Tags should be empty after clear_tags");
}

/// 测试文件元数据 (Metadata) 的完整生命周期
#[test]
fn test_v2_file_metadata_lifecycle() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "meta_file.txt", "meta content");
    let hash = vault.add_file(&file_path, &VaultPath::from("/meta_file.txt")).unwrap();

    // 2. 验证初始状态 (4个系统元数据)
    let initial_entry = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert_eq!(initial_entry.metadata.len(), 4, "Should have 4 system metadata entries");
    assert!(initial_entry.metadata.iter().any(|m| m.key == META_FILE_ADD_TIME));
    assert!(initial_entry.metadata.iter().any(|m| m.key == META_FILE_UPDATE_TIME));
    assert!(initial_entry.metadata.iter().any(|m| m.key == META_FILE_SIZE));
    assert!(initial_entry.metadata.iter().any(|m| m.key == META_SOURCE_MODIFIED_TIME));

    let initial_update_time = initial_entry.metadata.iter()
        .find(|m| m.key == META_FILE_UPDATE_TIME).unwrap().value.clone();

    // 确保时间戳可以更新
    thread::sleep(Duration::from_millis(5));

    // 3. 设置新元数据
    let meta_entry = MetadataEntry { key: "user_key".to_string(), value: "value1".to_string() };
    vault.set_file_metadata(&hash, meta_entry).unwrap();

    let entry_after_set = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert_eq!(entry_after_set.metadata.len(), 5, "Metadata count should be 5 after add");
    let custom_meta = entry_after_set.metadata.iter().find(|m| m.key == "user_key").unwrap();
    assert_eq!(custom_meta.value, "value1");

    // 4. 验证文件更新时间戳
    let update_time_after_set = entry_after_set.metadata.iter()
        .find(|m| m.key == META_FILE_UPDATE_TIME).unwrap().value.clone();
    assert_ne!(initial_update_time, update_time_after_set, "File update time should change after setting metadata");

    // 5. 更新元数据 (Upsert)
    let meta_entry_update = MetadataEntry { key: "user_key".to_string(), value: "value2".to_string() };
    vault.set_file_metadata(&hash, meta_entry_update).unwrap();

    let entry_after_update = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert_eq!(entry_after_update.metadata.len(), 5, "Metadata count should still be 5");
    let custom_meta_updated = entry_after_update.metadata.iter().find(|m| m.key == "user_key").unwrap();
    assert_eq!(custom_meta_updated.value, "value2");

    // 6. 移除元数据
    vault.remove_file_metadata(&hash, "user_key").unwrap();
    let entry_after_remove = match vault.find_by_hash(&hash).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert_eq!(entry_after_remove.metadata.len(), 4, "Metadata count should be 4 after remove");
    assert!(entry_after_remove.metadata.iter().find(|m| m.key == "user_key").is_none());

    // 7. 移除不存在的元数据 (应为静默成功)
    let remove_result = vault.remove_file_metadata(&hash, "non_existent_key");
    assert!(remove_result.is_ok());
}

/// 测试仓库元数据 (Vault Metadata) 的完整生命周期
#[test]
fn test_v2_vault_metadata_lifecycle() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);

    // 2. 验证初始状态 (Get)
    let create_time = vault.get_vault_metadata(META_VAULT_CREATE_TIME).unwrap();
    let update_time = vault.get_vault_metadata(META_VAULT_UPDATE_TIME).unwrap();
    assert_eq!(create_time, update_time, "Create and Update time should match on creation");

    let get_err = vault.get_vault_metadata("non_existent");
    assert!(matches!(get_err, Err(UpdateError::MetadataKeyNotFound(_))), "Should return KeyNotFound error");

    // 确保时间戳可以更新
    thread::sleep(Duration::from_millis(5));

    // 3. 设置 (Set)
    let meta_entry = MetadataEntry { key: "custom_key".to_string(), value: "custom_value".to_string() };
    vault.set_vault_metadata(meta_entry).unwrap();

    // 4. 验证 Get 和 Update Time
    let custom_value = vault.get_vault_metadata("custom_key").unwrap();
    assert_eq!(custom_value, "custom_value");

    let update_time_after_set = vault.get_vault_metadata(META_VAULT_UPDATE_TIME).unwrap();
    assert_ne!(create_time, update_time_after_set, "Update time should change after set_vault_metadata");

    // 5. 更新 (Upsert)
    let meta_entry_update = MetadataEntry { key: "custom_key".to_string(), value: "new_value".to_string() };
    vault.set_vault_metadata(meta_entry_update).unwrap();
    let custom_value_new = vault.get_vault_metadata("custom_key").unwrap();
    assert_eq!(custom_value_new, "new_value");

    // 6. 移除 (Remove)
    vault.remove_vault_metadata("custom_key").unwrap();
    let get_err_after_remove = vault.get_vault_metadata("custom_key");
    assert!(matches!(get_err_after_remove, Err(UpdateError::MetadataKeyNotFound(_))), "Should return KeyNotFound after remove");

    // 7. 移除不存在的键 (应失败)
    let remove_err = vault.remove_vault_metadata("non_existent_key");
    assert!(matches!(remove_err, Err(UpdateError::MetadataKeyNotFound(_))), "Removing non-existent key should fail");
}

// --- [新增] 辅助函数：创建多个虚拟文件 ---
/// 辅助：在临时目录中创建多个虚拟文件
/// 返回 (路径, 内容) 的元组列表
fn create_dummy_files(dir: &TempDir, count: usize, prefix: &str) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    for i in 0..count {
        let file_name = format!("{}_{:03}.txt", prefix, i);
        let content = format!("content for file {} {}!", prefix, i);
        let file_path = dir.path().join(&file_name);
        fs::write(&file_path, &content).unwrap();
        files.push((file_path, content));
    }
    files
}


// --- [新增] V2 并行 API 测试 ---

#[test]
fn test_v2_parallel_add_and_extract_lifecycle() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, vault) = setup_encrypted_vault(&dir);
    // 模拟 CLI 的共享状态
    let vault_arc = Arc::new(Mutex::new(vault));

    const FILE_COUNT: usize = 20; // 并行处理 20 个文件
    let source_files = create_dummy_files(&dir, FILE_COUNT, "parallel_add");

    let mut source_and_dest = Vec::new();
    for (i, (source_path, _content)) in source_files.iter().enumerate() {
        let dest_path = VaultPath::from(format!("/batch1/file_{:03}.txt", i).as_str());
        source_and_dest.push((source_path.clone(), dest_path));
    }

    // --- 2. 阶段 1: 并行加密 (ADD) ---
    println!("Testing parallel encryption...");
    let data_dir_path = vault_arc.lock().unwrap().get_data_dir_path(); // 1. Lock (快速)
    // (锁在此处释放)

    let encryption_results: Vec<_> = source_and_dest
        .into_par_iter() // <-- 2. 并行 (无锁)
        .map(|(source_path, dest_path)| {
            // 调用独立的 standalone 函数
            encrypt_file_for_add_standalone(
                &data_dir_path,
                &source_path,
                &dest_path,
            )
        })
        .collect();

    // 3. 收集加密结果
    let mut files_to_commit = Vec::new();
    for result in encryption_results {
        assert!(result.is_ok(), "Encryption should succeed: {:?}", result.err());
        files_to_commit.push(result.unwrap());
    }
    assert_eq!(files_to_commit.len(), FILE_COUNT);

    // --- 4. 阶段 2: 批量提交 (ADD) ---
    println!("Testing batch commit...");
    {
        let mut vault_guard = vault_arc.lock().unwrap(); // 4. Lock (快速)
        let commit_result = vault_guard.commit_add_files(files_to_commit);
        assert!(commit_result.is_ok(), "Commit should succeed");
    } // (锁在此处释放)

    // 5. 验证添加
    let all_files = vault_arc.lock().unwrap().list_all().unwrap();
    assert_eq!(all_files.len(), FILE_COUNT, "All files should be in the vault");
    let all_hashes: Vec<VaultHash> = all_files.iter().map(|f| f.sha256sum.clone()).collect();

    // --- 6. 阶段 1: 准备提取 (EXTRACT) ---
    println!("Testing parallel extraction preparation...");
    let extract_dir = dir.path().join("extracted_files");
    fs::create_dir_all(&extract_dir).unwrap();

    let tasks: Vec<(ExtractionTask, PathBuf)> = {
        let vault_guard = vault_arc.lock().unwrap(); // 1. Lock (快速)
        all_hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                // 调用快速的 prepare 实例方法
                let task = vault_guard.prepare_extraction_task(hash).unwrap();
                let dest_path = extract_dir.join(format!("extracted_file_{:03}.txt", i));
                (task, dest_path)
            })
            .collect()
    }; // (锁在此处释放)
    assert_eq!(tasks.len(), FILE_COUNT);

    // --- 7. 阶段 2: 并行执行 (EXTRACT) ---
    println!("Testing parallel execution...");
    let extract_results: Vec<_> = tasks
        .par_iter() // <-- 2. 并行 (无锁)
        .map(|(task, dest_path)| {
            // 调用独立的 standalone 函数
            execute_extraction_task_standalone(task, dest_path)
        })
        .collect();

    // 8. 验证提取
    for result in extract_results {
        assert!(result.is_ok(), "Extraction should succeed: {:?}", result.err());
    }

    // --- 9. 验证完整性 ---
    println!("Verifying integrity...");
    // 重新获取原始文件内容并与提取的文件内容进行比较
    let mut original_contents: Vec<String> = source_files.into_iter().map(|(_, content)| content).collect();
    original_contents.sort(); // 确保顺序一致

    let mut extracted_contents = Vec::new();
    for i in 0..FILE_COUNT {
        let dest_path = extract_dir.join(format!("extracted_file_{:03}.txt", i));
        let content = fs::read_to_string(dest_path).unwrap();
        extracted_contents.push(content);
    }
    extracted_contents.sort(); // 确保顺序一致

    assert_eq!(original_contents, extracted_contents, "Original and extracted contents must match");
    println!("Parallel add and extract cycle completed successfully.");
}

/// 测试 V2 扩展功能机制 (Feature Flags)
#[test]
fn test_v2_extension_features() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);

    // 2. 验证初始状态 (无任何功能启用)
    let initial_features = vault.get_enabled_features().unwrap();
    assert!(initial_features.is_empty(), "Should start with no features enabled");

    assert_eq!(vault.is_feature_enabled("compression_v1").unwrap(), false);

    // 3. 启用一个功能
    vault.enable_feature("compression_v1").unwrap();

    // 4. 验证启用状态
    assert_eq!(vault.is_feature_enabled("compression_v1").unwrap(), true);
    let features_step1 = vault.get_enabled_features().unwrap();
    assert_eq!(features_step1, vec!["compression_v1"]);

    // 5. 启用第二个功能 (验证追加逻辑)
    vault.enable_feature("smart_tags").unwrap();

    let features_step2 = vault.get_enabled_features().unwrap();
    assert_eq!(features_step2.len(), 2);
    assert!(features_step2.contains(&"compression_v1".to_string()));
    assert!(features_step2.contains(&"smart_tags".to_string()));

    // 6. 重复启用同一个功能 (应该是幂等的)
    vault.enable_feature("compression_v1").unwrap();
    let features_step3 = vault.get_enabled_features().unwrap();
    assert_eq!(features_step3.len(), 2, "Duplicate enable should not add duplicates");

    // 7. 错误处理：尝试启用带空格的名称
    let err = vault.enable_feature("invalid feature name");
    assert!(matches!(err, Err(UpdateError::InvalidFeatureName(_))));

    // 8. 持久化测试：重新打开保险库
    let vault_path = vault.root_path.clone();
    drop(vault); // 关闭连接

    let reopened_vault = Vault::open_vault(&vault_path, Some("v2-password")).unwrap();
    assert_eq!(reopened_vault.is_feature_enabled("compression_v1").unwrap(), true);
    assert_eq!(reopened_vault.is_feature_enabled("smart_tags").unwrap(), true);
    assert_eq!(reopened_vault.is_feature_enabled("non_existent").unwrap(), false);

    println!("Extension feature test passed!");
}