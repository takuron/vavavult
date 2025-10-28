use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::common::metadata::MetadataEntry;

/// 代表 `master.json` 配置文件的顶层结构 (V2)。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    /// 保险库的名称
    pub name: String,
    /// 保险库版本号，对于V2将固定为 2
    pub version: u32,
    /// 数据库是否加密。
    /// true 表示 master.db 使用 SQLCipher 加密。
    pub encrypted: bool,
    /// 用于验证保险库主密码的加密检查数据的字符串，格式为 "raw:encrypt(base64)"
    pub encrypt_check: String,
    /// 数据库文件的路径 (例如 "master.db")
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