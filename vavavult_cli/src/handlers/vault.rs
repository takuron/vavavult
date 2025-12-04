use std::error::Error;
use chrono::Local;
use vavavult::common::constants::{META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use vavavult::vault::Vault;
use crate::utils::parse_rfc3339_string;

/// 处理 vault 重命名命令
pub fn handle_vault_rename(vault: &mut Vault, new_name: &str) -> Result<(), Box<dyn Error>> {
    let old_name = vault.config.name.clone();

    // 调用核心库的 set_name 方法
    vault.set_name(new_name)?;

    println!("Vault successfully renamed from '{}' to '{}'.", old_name, new_name);
    Ok(())
}

pub fn handle_status(vault: &Vault) -> Result<(), Box<dyn Error>> {
    // 使用新的高效计数 API
    let file_count = vault.get_file_count()?;

    // 获取已启用的功能列表
    let features = vault.get_enabled_features()?;
    let features_display = if features.is_empty() {
        "None".to_string()
    } else {
        features.join(", ")
    };

    // 一个辅助函数，用于查找、解析、并格式化时间
    let format_time = |key: &str| -> String {
        // 使用 get_vault_metadata 从数据库获取
        vault.get_vault_metadata(key)
            .ok() // 将 Result 转换为 Option
            .and_then(|value| parse_rfc3339_string(&value).ok())
            .map(|utc_time| {
                // 转换为本地时区并格式化
                let local_time = utc_time.with_timezone(&Local);
                local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string()
            })
            .unwrap_or_else(|| "N/A".to_string()) // 如果失败则返回 "N/A"
    };

    let create_time_local = format_time(META_VAULT_CREATE_TIME);
    let update_time_local = format_time(META_VAULT_UPDATE_TIME);

    // 检查布尔值
    let encryption_status = if vault.config.encrypted {
        "Enabled"
    } else {
        "Disabled"
    };

    println!("--- Vault Status ---");
    println!("  Name:           {}", vault.config.name);
    println!("  Path:           {:?}", vault.root_path);
    println!("  Version:        {}", vault.config.version);
    println!("  Features:       {}", features_display);
    println!("  Encryption:     {}", encryption_status);
    println!("  Total Files:    {}", file_count);
    println!("  Created At:     {}", create_time_local);
    println!("  Last Updated:   {}", update_time_local);
    println!("--------------------");

    Ok(())
}