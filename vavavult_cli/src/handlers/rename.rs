use std::error::Error;
use vavavult::vault::Vault;

pub fn handle_rename(vault: &mut Vault, new_name: &str) -> Result<(), Box<dyn Error>> {
    let old_name = vault.config.name.clone();

    // 调用核心库的 set_name 方法
    vault.set_name(new_name)?;

    println!("Vault successfully renamed from '{}' to '{}'.", old_name, new_name);
    Ok(())
}