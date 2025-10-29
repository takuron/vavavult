use std::fs;
use tempfile::tempdir;
use vavavult::common::constants::{CURRENT_VAULT_VERSION, META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use vavavult::file::encrypt::verify_v2_encrypt_check;
use vavavult::vault::{CreateError, OpenError, Vault};

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