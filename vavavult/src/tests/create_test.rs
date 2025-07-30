use std::fs;
use tempfile::tempdir;
use crate::vault::{Vault, VaultConfig};
// 使用 tempfile 库来创建临时目录，避免污染文件系统

#[test]
fn test_create_vault_success() {
    // 1. 创建一个临时目录用于测试
    let dir = tempdir().unwrap();
    let vault_path = dir.path();

    // 2. 调用我们的初始化函数
    let result = Vault::create_vault(vault_path, "my-test-vault");

    // 3. 断言操作成功
    assert!(result.is_ok());
    let vault = result.unwrap();
    let config = vault.config;
    assert_eq!(config.name, "my-test-vault");

    // 4. 验证文件是否已正确创建
    let master_json_path = vault_path.join("master.json");
    assert!(master_json_path.exists());
    assert!(master_json_path.is_file());

    let filelist_path = vault_path.join("master.db");
    assert!(filelist_path.exists());
    assert!(filelist_path.is_file());

    // 5. 验证文件内容
    let master_json_content = fs::read_to_string(master_json_path).unwrap();
    let parsed_config: VaultConfig = serde_json::from_str(&master_json_content).unwrap();
    assert_eq!(parsed_config.name, "my-test-vault");
    assert_eq!(parsed_config.encrypt_check.encrypted, "");

    // 临时目录会在 `dir` 离开作用域时自动被清理
}