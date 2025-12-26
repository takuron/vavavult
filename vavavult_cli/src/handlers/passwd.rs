use crate::errors::CliError;
use std::path::PathBuf;
use vavavult::vault::Vault;

pub fn handle_passwd(vault_path: &PathBuf) -> Result<Vault, CliError> {
    if !vault_path.exists() {
        return Err(CliError::VaultNotFound(vault_path.clone()));
    }

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

    // First, update the password for the (closed) vault.
    Vault::update_password(vault_path, &old_password, &new_password)?;

    println!("Vault password updated successfully. Opening vault...");

    // Now, open the vault with the new password to start a session.
    let vault = Vault::open_vault_local(vault_path, Some(&new_password))?;

    Ok(vault)
}
