use std::error::Error;
use chrono::{Local};
use vavavult::vault::Vault;
use vavavult::common::constants::{META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use vavavult::utils::time as time_utils;

pub fn handle_status(vault: &Vault) -> Result<(), Box<dyn Error>> {
    let file_count = vault.list_all()?.len();

    // 一个辅助函数，用于查找、解析、并格式化时间
    let format_time = |key: &str| -> String {
        vault.config.metadata.iter()
            .find(|m| m.key == key)
            .and_then(|m| time_utils::parse_rfc3339_string(&m.value).ok()) // 解析为 UTC 时间
            .map(|utc_time| {
                // 转换为本地时区并格式化
                let local_time = utc_time.with_timezone(&Local);
                local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string()
            })
            .unwrap_or_else(|| "N/A".to_string()) // 如果失败则返回 "N/A"
    };

    let create_time_local = format_time(META_VAULT_CREATE_TIME);
    let update_time_local = format_time(META_VAULT_UPDATE_TIME);

    println!("--- Vault Status ---");
    println!("  Name:           {}", vault.config.name);
    println!("  Path:           {:?}", vault.root_path);
    println!("  Version:        {}", vault.config.version);
    println!("  Encryption:     {:?}", vault.config.encrypt_type);
    println!("  Total Files:    {}", file_count);
    println!("  Created At:     {}", create_time_local); // 使用本地化时间
    println!("  Last Updated:   {}", update_time_local); // 使用本地化时间
    println!("--------------------");

    Ok(())
}