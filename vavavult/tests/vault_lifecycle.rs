use std::fs;
use std::sync::Arc;
use tempfile::tempdir;
use vavavult::common::constants::{
    CURRENT_VAULT_VERSION, META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME,
};
use vavavult::storage::local::LocalStorage;
use vavavult::vault::{CreateError, OpenError, UpdateError, Vault};

// 引入 common 模块
mod common;

/// 测试：成功创建一个非加密的保险库。
/// 验证点：
/// 1. 配置文件 (master.json) 正确生成，且 version, name, encrypted 字段正确。
/// 2. 数据库文件 (master.db) 存在。
/// 3. 数据库内初始化了系统元数据 (创建时间)。
#[test]
fn test_create_non_encrypted_vault_success() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("v3-non-encrypted");
    let vault_name = "my-v3-test-vault";

    let result = Vault::create_vault_local(&vault_path, vault_name, None);
    assert!(result.is_ok());
    let vault = result.unwrap();

    // 验证内存中的配置状态
    assert_eq!(vault.config.name, vault_name);
    assert_eq!(vault.config.version, CURRENT_VAULT_VERSION);
    assert!(!vault.config.encrypted);
    assert!(vault.config.encrypt_check.is_empty());

    // 验证磁盘文件结构
    assert!(vault_path.join("master.json").exists());
    assert!(vault_path.join("master.db").exists());

    // 验证数据库元数据表是否初始化
    let create_time: String = vault.get_vault_metadata(META_VAULT_CREATE_TIME).unwrap();
    let update_time: String = vault.get_vault_metadata(META_VAULT_UPDATE_TIME).unwrap();
    assert!(!create_time.is_empty());
    assert_eq!(create_time, update_time);
}

/// 测试：新建保险库时初始化多对一硬链接数据库结构。
/// 验证点：
/// 1. `files` 表不再包含完整路径 `path` 字段。
/// 2. `directories` 和 `file_entries` 表存在。
/// 3. `directories` 表默认包含一条根目录记录。
#[test]
fn test_create_vault_initializes_hardlink_schema() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("hardlink-schema");

    let vault = Vault::create_vault_local(&vault_path, "schema-test", None).unwrap();
    let conn = &vault.database_connection;

    let file_columns = conn
        .prepare("PRAGMA table_info(files)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        file_columns,
        vec!["sha256sum", "original_sha256sum", "encrypt_password"]
    );

    let directory_columns = conn
        .prepare("PRAGMA table_info(directories)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(directory_columns, vec!["id", "parent_id", "name"]);

    let file_entry_columns = conn
        .prepare("PRAGMA table_info(file_entries)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        file_entry_columns,
        vec!["id", "directory_id", "name", "file_sha256sum"]
    );

    let root_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM directories WHERE id = 1 AND parent_id IS NULL AND name = ''",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(root_count, 1);
}

/// 测试：成功创建一个加密的保险库。
/// 验证点：
/// 1. 配置中 `encrypted` 标志为 true。
/// 2. 生成了 `encrypt_check` 字符串。
/// 3. `encrypt_check` 能够被正确密码验证，并拒绝错误密码。
#[test]
fn test_create_encrypted_vault_success() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("v3-encrypted");
    let vault_name = "my-v3-secure-vault";
    let password = "v3-password-!@#";

    // 1. 创建
    let backend = Arc::new(LocalStorage::new(&vault_path));
    // 注意：我们需要 clone backend，因为 create_vault 会消耗它，
    // 而我们稍后在 open_vault 测试中还需要用到它 (或者创建新的)。
    let result = Vault::create_vault(&vault_path, vault_name, Some(password), backend.clone());
    assert!(result.is_ok());
    let vault = result.unwrap();

    // 2. 验证基本配置
    assert!(vault.config.encrypted);
    assert!(!vault.config.encrypt_check.is_empty());

    // 验证密码逻辑 (不再调用私有函数，而是通过公开 API 验证行为)

    // a. 释放旧的 vault 实例 (模拟关闭，虽然这里不是必须的，但更严谨)
    drop(vault);

    // b. 尝试使用错误密码打开 -> 应该失败 (InvalidPassword)
    let open_fail = Vault::open_vault(&vault_path, Some("wrong-password"), backend.clone());
    assert!(matches!(open_fail.unwrap_err(), OpenError::InvalidPassword));

    // c. 尝试使用正确密码打开 -> 应该成功
    let open_success = Vault::open_vault(&vault_path, Some(password), backend.clone());
    assert!(
        open_success.is_ok(),
        "Should be able to open vault with correct password"
    );
}

/// 测试：尝试在非空目录创建保险库应报错。
/// 这是一个安全特性，防止覆盖现有数据。
#[test]
fn test_create_vault_already_exists_error() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("existing-dir");
    fs::create_dir_all(&vault_path).unwrap();
    // 制造一个非空目录
    fs::write(vault_path.join("dummy.txt"), "content").unwrap();

    let result = Vault::create_vault_local(&vault_path, "test", None);
    // 断言返回特定的 VaultAlreadyExists 错误
    assert!(matches!(
        result.unwrap_err(),
        CreateError::VaultAlreadyExists(_)
    ));
}

/// 测试：保险库的持久化能力 (打开-关闭-重开)。
/// 验证在 Vault 对象 Drop 后，重新打开能恢复之前的状态。
#[test]
fn test_open_and_reopen_vault_cycle() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("persistent-vault");
    let vault_name = "persist-test";

    // 1. 创建并立即 Drop (模拟程序关闭)
    {
        let vault = Vault::create_vault_local(&vault_path, vault_name, None).unwrap();
        assert_eq!(vault.config.name, vault_name);
    }

    // 2. 重新打开
    let reopened_vault = Vault::open_vault_local(&vault_path, None).unwrap();
    assert_eq!(reopened_vault.config.name, vault_name);
}

/// 测试：加密保险库的访问控制。
/// 验证：
/// 1. 不提供密码时拒绝访问。
/// 2. 提供错误密码时拒绝访问。
/// 3. 提供正确密码时允许访问。
#[test]
fn test_open_encrypted_vault_access_control() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("secure-vault");
    let password = "v3-super-secret";

    // 创建
    {
        Vault::create_vault_local(&vault_path, "access-control", Some(password)).unwrap();
    }

    // 场景 1: 未提供密码
    assert!(matches!(
        Vault::open_vault_local(&vault_path, None).unwrap_err(),
        OpenError::PasswordRequired
    ));

    // 场景 2: 密码错误
    assert!(matches!(
        Vault::open_vault_local(&vault_path, Some("wrong")).unwrap_err(),
        OpenError::InvalidPassword
    ));

    // 场景 3: 密码正确
    assert!(Vault::open_vault_local(&vault_path, Some(password)).is_ok());
}

/// 测试：扩展功能 (Feature Flags) 的管理。
/// 验证功能的启用、查询以及对非法功能名的校验。
#[test]
fn test_extension_features() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = common::setup_encrypted_vault(&dir);

    // 初始为空
    assert!(vault.get_enabled_features().unwrap().is_empty());
    assert!(!vault.is_feature_enabled("compression_v1").unwrap());

    // 启用一个功能
    vault.enable_feature("compression_v1").unwrap();
    assert!(vault.is_feature_enabled("compression_v1").unwrap());

    // 启用第二个功能
    vault.enable_feature("smart_tags").unwrap();
    let features = vault.get_enabled_features().unwrap();
    assert_eq!(features.len(), 2);
    assert!(features.contains(&"compression_v1".to_string()));

    // 错误处理：功能名不能包含空格
    let err = vault.enable_feature("invalid feature name");
    assert!(matches!(err, Err(UpdateError::InvalidFeatureName(_))));
}

/// 测试：尝试打开旧版本 (V2) 的保险库应报错。
/// 验证 "阻止读取所有版本号不是 3 的文件库" 的要求。
#[test]
fn test_open_v2_vault_should_fail() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("old-v2-vault");
    fs::create_dir_all(&vault_path).unwrap();

    // 手动创建一个 V2 格式的 master.json
    let v2_config = serde_json::json!({
        "name": "old-vault",
        "version": 2,
        "encrypted": false,
        "encryptCheck": "",
        "database": "master.db"
    });
    fs::write(vault_path.join("master.json"), v2_config.to_string()).unwrap();
    // 还需要一个空的数据库文件，否则会报 DatabaseNotFound 而不是 UnsupportedVersion
    fs::write(vault_path.join("master.db"), "").unwrap();

    let result = Vault::open_vault_local(&vault_path, None);

    match result {
        Err(OpenError::UnsupportedVersion { supported, found }) => {
            assert_eq!(supported, 3);
            assert_eq!(found, 2);
        }
        _ => panic!("Expected UnsupportedVersion error, got {:?}", result),
    }
}

