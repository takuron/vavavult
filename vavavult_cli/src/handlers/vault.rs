use crate::core::helpers::parse_rfc3339_string;
use crate::errors::CliError;
use crate::repl::state::AppState;
use crate::ui::printer::print_status;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vavavult::common::constants::{META_VAULT_CREATE_TIME, META_VAULT_UPDATE_TIME};
use vavavult::vault::Vault;

// This struct is a DTO for the printer
pub struct VaultStatus {
    pub name: String,
    pub path: PathBuf,
    pub version: String,
    pub features: Vec<String>,
    pub encrypted: bool,
    pub file_count: i64,
    pub storage_file_count: i64,
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

/// Gathers vault status information and prints it.
pub fn handle_status(vault: &Vault) -> Result<(), CliError> {
    let file_count = vault.get_file_count()?;
    let storage_file_count = vault.get_storage_file_count()?;
    let features = vault.get_enabled_features()?;

    let get_time = |key: &str| -> Option<DateTime<Utc>> {
        vault
            .get_vault_metadata(key)
            .ok()
            .and_then(|value| parse_rfc3339_string(&value).ok())
    };

    let status = VaultStatus {
        name: vault.config.name.clone(),
        path: vault.root_path.clone(),
        version: vault.config.version.to_string(),
        features,
        encrypted: vault.config.encrypted,
        file_count,
        storage_file_count,
        created_at: get_time(META_VAULT_CREATE_TIME),
        updated_at: get_time(META_VAULT_UPDATE_TIME),
    };

    print_status(&status);

    Ok(())
}

/// 处理保险库密码修改命令。
///
/// 此函数执行"浅层"密码更新（重新加密数据库密钥），并可选地通过 `--rekey`
/// 标志轮换所有文件的加密密钥以进行完全重加密。
///
/// 由于此操作需要关闭并重新打开保险库连接，因此它直接操作 `AppState`
/// 来替换活动的保险库实例。
pub fn handle_vault_passwd(app_state: &mut AppState, rekey: bool) -> Result<(), CliError> {
    // 1. 获取当前保险库路径和加密状态（在关闭连接之前）
    let (vault_path, is_encrypted) = {
        let vault_arc = app_state
            .active_vault
            .as_ref()
            .ok_or(CliError::VaultNotOpen)?;
        let vault = vault_arc.lock().unwrap();
        (vault.root_path.clone(), vault.config.encrypted)
    };

    // 2. 检查是否为加密保险库
    if !is_encrypted {
        println!("This vault is not encrypted. Password change is not applicable.");
        return Ok(());
    }

    // 3. 交互式获取新旧密码
    let old_password = rpassword::prompt_password("Enter old password: ")?;
    let new_password = rpassword::prompt_password("Enter new password: ")?;
    let new_password_confirm = rpassword::prompt_password("Confirm new password: ")?;

    if new_password != new_password_confirm {
        return Err(CliError::PasswordMismatch);
    }

    if new_password.is_empty() {
        return Err(CliError::InvalidName(
            "Password cannot be empty.".to_string(),
        ));
    }

    // 4. 关闭当前保险库连接，释放数据库锁
    drop(app_state.active_vault.take());

    // 5. 执行浅层密码更新（重新加密数据库密钥 + 更新 master.json）
    Vault::update_password(&vault_path, &old_password, &new_password)?;
    println!("Vault password updated successfully.");

    // 6. 用新密码重新打开保险库
    let mut vault = Vault::open_vault_local(&vault_path, Some(&new_password))?;

    // 7. 如果指定了 --rekey，对所有文件执行完全重加密
    if rekey {
        println!("Starting full re-encryption of all files...");

        // 获取保险库中所有唯一文件的哈希
        let all_files = vault.list_all()?;
        let hashes: Vec<_> = all_files.iter().map(|f| f.sha256sum.clone()).collect();
        let total = hashes.len();

        if total == 0 {
            println!("No files to re-encrypt.");
        } else {
            // 分批处理以避免长时间持有数据库锁
            let batch_size = 100;
            let batches = (total + batch_size - 1) / batch_size;

            for (i, chunk) in hashes.chunks(batch_size).enumerate() {
                println!(
                    "Re-encrypting batch {}/{} ({} files)...",
                    i + 1,
                    batches,
                    chunk.len()
                );

                // 阶段1: 准备密钥轮换任务（验证哈希）
                let pending = vault.prepare_rekey_tasks(chunk)?;

                // 阶段2: 对每个文件执行重加密（I/O 和 CPU 密集型）
                let storage = Arc::clone(&vault.storage);
                let mut rekey_tasks = Vec::with_capacity(pending.len());
                for task in pending {
                    let rekeyed = Vault::rekey_task(storage.as_ref(), task)?;
                    rekey_tasks.push(rekeyed);
                }

                // 阶段3: 原子化提交到数据库和文件系统
                vault.commit_rekey_tasks(rekey_tasks)?;
            }

            println!("Full re-encryption complete. {} files processed.", total);
        }
    }

    // 8. 更新 AppState 以使用新的保险库实例
    app_state.active_vault = Some(Arc::new(Mutex::new(vault)));

    println!("Vault is now open with the new password.");
    Ok(())
}
