use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Represents the top-level structure of the `master.json` configuration file.
///
/// This struct holds global settings for the vault, such as its name, version,
/// encryption status, and the location of the database file.
//
// // 代表 `master.json` 配置文件的顶层结构。
// //
// // 此结构体保存保险库的全局设置，例如名称、版本、加密状态以及数据库文件的位置。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    /// The name of the vault.
    // // 保险库的名称。
    pub name: String,

    /// The vault version number. Fixed at 2 for V2 vaults.
    // // 保险库版本号。对于 V2 保险库固定为 2。
    pub version: u32,

    /// Indicates whether the vault database is encrypted.
    /// If `true`, `master.db` is encrypted using SQLCipher.
    // // 指示保险库数据库是否已加密。
    // // 如果为 `true`，则 `master.db` 使用 SQLCipher 进行加密。
    pub encrypted: bool,

    /// A validation string used to verify the vault's master password.
    /// Format: "raw:encrypted(base64)".
    // // 用于验证保险库主密码的校验字符串。
    // // 格式: "raw:encrypted(base64)"。
    pub encrypt_check: String,

    /// The relative path to the SQLite database file (e.g., "master.db").
    // // SQLite 数据库文件的相对路径 (例如 "master.db")。
    pub database: PathBuf,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::vault::config::VaultConfig;

    #[test]
    fn test_deserialize_v2_vault_config(){
        let json_v2 = r#"
        {
            "name": "v2_vault",
            "version": 2,
            "encrypted": true,
            "encryptCheck": "v2_check:SGVsbG8=",
            "database": "master.db"
        }
        "#;
        let config: VaultConfig = serde_json::from_str(json_v2).unwrap();

        assert_eq!(config.name, "v2_vault");
        assert_eq!(config.version, 2);
        assert_eq!(config.encrypted, true);
        assert_eq!(config.encrypt_check, "v2_check:SGVsbG8=");
    }

    #[test]
    fn test_serialize_v2_vault_config() {
        let config_v2 = VaultConfig {
            name: "my_v2_vault".to_string(),
            version: 2,
            encrypted: false,
            encrypt_check: "".to_string(),
            database: PathBuf::from("master.db"),
        };

        let json_string = serde_json::to_string(&config_v2).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&json_string).unwrap();

        assert_eq!(json_value["version"].as_u64(), Some(2));
        assert_eq!(json_value["name"].as_str(), Some("my_v2_vault"));
        assert_eq!(json_value["encrypted"].as_bool(), Some(false));
        assert_eq!(json_value["encryptCheck"].as_str(), Some(""));
        assert!(json_value["metadata"].is_null()); // 确认 metadata 字段已不存在
    }
}