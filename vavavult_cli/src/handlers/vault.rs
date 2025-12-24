use crate::core::helpers::parse_rfc3339_string;
use crate::errors::CliError;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use vavavult::common::constants::{META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use vavavult::vault::Vault;

/// Contains the data for the vault status, to be processed by a view/printer.
pub struct VaultStatus {
    pub name: String,
    pub path: PathBuf,
    pub version: String,
    pub features: Vec<String>,
    pub encrypted: bool,
    pub file_count: i64,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// 处理 vault 重命名命令
pub fn handle_vault_rename(vault: &mut Vault, new_name: &str) -> Result<(), CliError> {
    let old_name = vault.config.name.clone();

    // 调用核心库的 set_name 方法
    vault.set_name(new_name)?;

    println!(
        "Vault successfully renamed from '{}' to '{}'.",
        old_name, new_name
    );
    Ok(())
}

/// Gathers vault status information and returns it as a struct.
pub fn handle_status(vault: &Vault) -> Result<VaultStatus, CliError> {
    let file_count = vault.get_file_count()?;
    let features = vault.get_enabled_features()?;

    let get_time = |key: &str| -> Option<DateTime<Utc>> {
        vault
            .get_vault_metadata(key)
            .ok()
            .and_then(|value| parse_rfc3339_string(&value).ok())
    };

    let created_at = get_time(META_VAULT_CREATE_TIME);
    let updated_at = get_time(META_VAULT_UPDATE_TIME);

    Ok(VaultStatus {
        name: vault.config.name.clone(),
        path: vault.root_path.clone(),
        version: vault.config.version.to_string(),
        features,
        encrypted: vault.config.encrypted,
        file_count,
        created_at,
        updated_at,
    })
}
