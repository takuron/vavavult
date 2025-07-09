use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::{EncryptionCheck, EncryptionType};

/// 代表 `master.json` 配置文件的顶层结构。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub name: String,
    pub version: u32,
    pub encrypt_type: EncryptionType,
    pub encrypt_check: EncryptionCheck,
    pub database: PathBuf,
    pub metadata: Vec<MetadataEntry>,
}

#[cfg(test)]

mod tests {
    use std::path::PathBuf;
    use crate::common::metadata::MetadataEntry;
    use crate::file::encrypt::{EncryptionCheck, EncryptionType};
    use crate::vault::config::VaultConfig;

    #[test]
    fn test_deserialize_vault_config(){
        let json1 = r#"
        {
            "name": "test_vault",
            "version": 1,
            "encryptType": 0,
            "encryptCheck": {
                "raw": "",
                "encrypted": ""
            },
            "database":"master.db",
            "metadata":[
                {
                    "key":"author",
                    "value":"takuron"
                }
            ]
        }
        "#;
        let config: VaultConfig = serde_json::from_str(json1).unwrap();

        assert_eq!(config.name, "test_vault");
        assert_eq!(config.version, 1);
        assert_eq!(config.encrypt_type, EncryptionType::None);
        assert_eq!(config.encrypt_check.raw, "");
        assert_eq!(config.metadata[0].value, "takuron");
    }
    #[test]
    fn test_serialize_vault_config() {
        let config1 = VaultConfig {
            name: "my_new_vault".to_string(),
            version: 1,
            encrypt_type: EncryptionType::None,
            encrypt_check: EncryptionCheck {
                raw: "".to_string(), // 对于不加密，可以为空字符串
                encrypted: "".to_string(),
            },
            database: PathBuf::from("master.db"),
            metadata: vec![
                MetadataEntry {
                    key: "author".to_string(),
                    value: "takuron".to_string(),
                }
            ],
        };

        let json_string = serde_json::to_string_pretty(&config1).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&json_string).unwrap();
        assert_eq!(json_value["encryptType"].as_u64(), Some(0));
        assert_eq!(json_value["name"].as_str(), Some("my_new_vault"));
        assert_eq!(json_value["encryptCheck"]["raw"].as_str(), Some(""));
    }

}