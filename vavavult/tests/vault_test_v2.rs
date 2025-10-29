use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::{tempdir, TempDir};
use vavavult::common::constants::{CURRENT_VAULT_VERSION, DATA_SUBDIR, META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use vavavult::file::encrypt::verify_v2_encrypt_check;
use vavavult::file::VaultPath;
use vavavult::vault::{AddFileError, CreateError, OpenError, QueryResult, UpdateError, Vault};

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
    assert_eq!(vault.config.version, CURRENT_VAULT_VERSION, "Version should be V2"); //
    assert_eq!(vault.config.encrypted, false, "Should not be encrypted");
    assert!(vault.config.encrypt_check.is_empty(), "Encrypt check should be empty for non-encrypted"); //

    // 4. 验证文件系统
    assert!(vault_path.join("master.json").exists());
    assert!(vault_path.join("master.db").exists());

    // 5. 验证数据库 (V2 特性：vault_metadata 表)
    let create_time: String = vault.database_connection.query_row(
        "SELECT meta_value FROM vault_metadata WHERE meta_key = ?1",
        [META_VAULT_CREATE_TIME],
        |row| row.get(0), // 编译器现在推断 T=String
    ).expect("Failed to query create_time");

    let update_time: String = vault.database_connection.query_row(
        "SELECT meta_value FROM vault_metadata WHERE meta_key = ?1",
        [META_VAULT_UPDATE_TIME],
        |row| row.get(0), // 编译器现在推断 T=String
    ).expect("Failed to query update_time");

    assert!(!create_time.is_empty(), "Create time metadata should be set in DB");
    assert_eq!(create_time, update_time, "Create and update time should be identical on creation");
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
    assert!(!vault.config.encrypt_check.is_empty(), "Encrypt check should NOT be empty"); //
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
    let table_count: i64 = vault.database_connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='vault_metadata'",
        [],
        |row| row.get(0),
    ).expect("Database query should succeed with correct password");

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
    assert!(matches!(no_pass_result.unwrap_err(), OpenError::PasswordRequired), "Should fail with PasswordRequired"); //

    // 3. 失败：尝试用错误密码打开
    let wrong_pass_result = Vault::open_vault(&vault_path, Some("wrong-password"));
    assert!(matches!(wrong_pass_result.unwrap_err(), OpenError::InvalidPassword), "Should fail with InvalidPassword"); //

    // 4. 成功：尝试用正确密码打开
    let correct_pass_result = Vault::open_vault(&vault_path, Some(password));
    assert!(correct_pass_result.is_ok(), "Should succeed with correct password");
    let vault = correct_pass_result.unwrap();
    assert_eq!(vault.config.name, "access-control");
}

/// 测试打开一个不存在的路径
#[test]
fn test_v2_open_nonexistent_vault() {
    let dir = tempdir().unwrap();
    let non_existent_path = dir.path().join("non-existent-vault");

    let result = Vault::open_vault(&non_existent_path, None);
    assert!(matches!(result.unwrap_err(), OpenError::PathNotFound(_)), "Should fail with PathNotFound"); //
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
    // [修改] 使用 find_by_path 和 &VaultPath
    let query_res = vault.find_by_path(&dest_path).unwrap();
    let entry = match query_res {
        QueryResult::Found(entry) => entry,
        QueryResult::NotFound => panic!("File not found by name after adding"),
    };
    assert_eq!(entry.path, "/docs/hello.txt");
    assert_eq!(entry.sha256sum, encrypted_hash);
    assert!(!entry.original_sha256sum.to_string().is_empty()); // 确保原始哈希存在
    assert_eq!(entry.metadata.len(), 4); // 4 个系统元数据

    // 4. 提取 (Act)
    let extract_path = dir.path().join("extracted_hello.txt");
    // [修改] extract_file 接受 &VaultHash, `encrypted_hash` 已经是该类型
    let extract_result = vault.extract_file(&encrypted_hash, &extract_path);
    assert!(extract_result.is_ok(), "extract_file should succeed");

    // 5. 验证提取 (Assert Extract)
    assert!(extract_path.exists(), "Extracted file should exist");
    let extracted_content = fs::read_to_string(&extract_path).unwrap();
    assert_eq!(extracted_content, "Hello V2 Integrity Check", "Extracted content must match original");

    // 6. 测试提取完整性检查失败 (损坏文件)
    let internal_path = vault.root_path.join(DATA_SUBDIR).join(encrypted_hash.to_string());
    fs::write(internal_path, "corrupted data").unwrap(); // 故意损坏保险库中的文件

    // [修改] extract_file 接受 &VaultHash
    let extract_fail_result = vault.extract_file(&encrypted_hash, &extract_path);
    assert!(extract_fail_result.is_err(), "Extract should fail on corrupted data");
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
    assert!(matches!(res_dup_path.unwrap_err(), AddFileError::DuplicateFileName(_)));

    // 4. 错误：使用相同内容 (file1) 添加到不同路径
    let path2 = VaultPath::from("/file1_copy.txt");
    let res_dup_content = vault.add_file(&file1_path, &path2);
    assert!(matches!(res_dup_content.unwrap_err(), AddFileError::DuplicateOriginalContent(_, _)));

    // 5. 成功：添加 file2 到一个目录
    let dir_path = VaultPath::from("/docs/");
    vault.add_file(&file2_path, &dir_path).unwrap();

    // 验证：文件应在 /docs/file2.txt
    // [修改] 使用 find_by_path
    let query_res = vault.find_by_path(&VaultPath::from("/docs/file2.txt")).unwrap();
    assert!(matches!(query_res, QueryResult::Found(_)));

    // 6. 错误：尝试将文件添加到无效的文件路径 (e.g. 包含 '..')
    // VaultPath::new 应该已经处理了规范化，但我们测试 add_file 的目标路径检查
    let invalid_path = VaultPath::from("/a/b/../c.txt"); // 规范化为 /a/c.txt
    assert!(vault.add_file(&file1_path, &invalid_path).is_err(), "Should fail, duplicate original content");

    // 7. 错误：尝试添加一个文件，其目标路径不是文件
    let path_as_dir = VaultPath::from("/looks/like/dir/");
    let file3_path = create_dummy_file(&dir, "file3.txt", "content3");
    // add_file 内部调用 resolve_final_path，它会附加文件名
    let add_res = vault.add_file(&file3_path, &path_as_dir);
    assert!(add_res.is_ok());
    // [修改] 使用 find_by_path
    assert!(matches!(vault.find_by_path(&VaultPath::from("/looks/like/dir/file3.txt")).unwrap(), QueryResult::Found(_)));
}

/// 测试 `move_file` 和 `rename_file_inplace`
#[test]
fn test_v2_move_and_rename_file() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "move_me.txt", "move content");
    let blocker_path = create_dummy_file(&dir, "blocker.txt", "blocker content");

    let hash = vault.add_file(&file_path, &VaultPath::from("/dir1/move_me.txt")).unwrap();
    let blocker_hash = vault.add_file(&blocker_path, &VaultPath::from("/dir2/blocker.txt")).unwrap();
    assert_ne!(hash, blocker_hash);

    // 2. 测试 `rename_file_inplace` (成功)
    // [修改] 接受 &VaultHash
    let rename_res = vault.rename_file_inplace(&hash, "renamed.txt");
    assert!(rename_res.is_ok());
    // [修改] 使用 find_by_path
    assert!(matches!(vault.find_by_path(&VaultPath::from("/dir1/move_me.txt")).unwrap(), QueryResult::NotFound));
    assert!(matches!(vault.find_by_path(&VaultPath::from("/dir1/renamed.txt")).unwrap(), QueryResult::Found(_)));

    // 3. 测试 `rename_file_inplace` (错误：无效名称)
    // [修改] 接受 &VaultHash
    let rename_err = vault.rename_file_inplace(&hash, "invalid/name.txt");
    assert!(matches!(rename_err.unwrap_err(), UpdateError::InvalidFilename(_)));

    // 4. 测试 `move_file` (成功：移动到目录)
    // [修改] 接受 &VaultHash
    let move_to_dir_res = vault.move_file(&hash, &VaultPath::from("/dir2/"));
    assert!(move_to_dir_res.is_ok());
    // [修改] 使用 find_by_path
    assert!(matches!(vault.find_by_path(&VaultPath::from("/dir1/renamed.txt")).unwrap(), QueryResult::NotFound));
    // 文件应保留其名称 "renamed.txt" 并移动到 /dir2/
    // [修改] 使用 find_by_path
    let query_res = vault.find_by_path(&VaultPath::from("/dir2/renamed.txt")).unwrap();
    match query_res {
        QueryResult::Found(entry) => assert_eq!(entry.sha256sum, hash),
        _ => panic!("File not found in new directory /dir2/"),
    }

    // 5. 测试 `move_file` (错误：路径冲突)
    // [修改] 接受 &VaultHash
    let move_conflict_res = vault.move_file(&hash, &VaultPath::from("/dir2/blocker.txt"));
    assert!(matches!(move_conflict_res.unwrap_err(), UpdateError::DuplicateTargetPath(_)));

    // 6. 测试 `move_file` (成功：移动并重命名)
    // [修改] 接受 &VaultHash
    let move_rename_res = vault.move_file(&hash, &VaultPath::from("/final_spot.txt"));
    assert!(move_rename_res.is_ok());
    // [修改] 使用 find_by_path
    assert!(matches!(vault.find_by_path(&VaultPath::from("/dir2/renamed.txt")).unwrap(), QueryResult::NotFound));
    assert!(matches!(vault.find_by_path(&VaultPath::from("/final_spot.txt")).unwrap(), QueryResult::Found(_)));
}

/// 测试 `remove_file`
#[test]
fn test_v2_remove_file() {
    // 1. 准备
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "delete_me.txt", "delete content");

    let hash = vault.add_file(&file_path, &VaultPath::from("/delete_me.txt")).unwrap();
    // [修改] 使用 &VaultHash
    let original_hash = match vault.find_by_hash(&hash) {
        Ok(QueryResult::Found(e)) => e.original_sha256sum,
        _ => panic!("File not found right after add"),
    };

    // 添加一些关联数据
    // [修改] 使用 &VaultHash
    vault.add_tag(&hash, "temp").unwrap();
    vault.set_file_metadata(&hash, vavavult::common::metadata::MetadataEntry {
        key: "custom_key".to_string(),
        value: "custom_value".to_string(),
    }).unwrap();

    // 验证物理文件存在
    let internal_path = vault.root_path.join(DATA_SUBDIR).join(hash.to_string());
    assert!(internal_path.exists(), "Internal data file should exist");

    // 2. 删除 (Act)
    // [修改] 接受 &VaultHash
    let remove_res = vault.remove_file(&hash);
    assert!(remove_res.is_ok());

    // 3. 验证 (Assert)
    // a. 数据库查询失败
    // [修改] 使用 find_by_path
    assert!(matches!(vault.find_by_path(&VaultPath::from("/delete_me.txt")).unwrap(), QueryResult::NotFound));
    // [修改] 使用 &VaultHash
    assert!(matches!(vault.find_by_hash(&hash).unwrap(), QueryResult::NotFound));
    // [修改] 使用 find_by_original_hash
    assert!(matches!(vault.find_by_original_hash(&original_hash).unwrap(), QueryResult::NotFound));

    // b. 物理文件被删除
    assert!(!internal_path.exists(), "Internal data file should be deleted");

    // c. 验证标签和元数据是否被级联删除 (通过查询空表)
    let tag_count: i64 = vault.database_connection.query_row(
        "SELECT COUNT(*) FROM tags WHERE file_sha256sum = ?1",
        [&hash], |row| row.get(0)).unwrap();
    assert_eq!(tag_count, 0, "Tags should be cascade deleted");

    let meta_count: i64 = vault.database_connection.query_row(
        "SELECT COUNT(*) FROM metadata WHERE file_sha256sum = ?1",
        [&hash], |row| row.get(0)).unwrap();
    assert_eq!(meta_count, 0, "Metadata should be cascade deleted");
}