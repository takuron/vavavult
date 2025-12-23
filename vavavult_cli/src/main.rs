mod cli;
pub mod errors;
mod handlers;
mod repl;
mod utils;

use crate::cli::{Cli, TopLevelCommands};
use crate::errors::CliError;
use crate::repl::run_repl;
use crate::repl::state::AppState;
use clap::Parser;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vavavult::vault::{OpenError, Vault};

fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    let vault_result: Result<Vault, CliError> = match cli.command {
        TopLevelCommands::Create { path } => {
            let parent_path = path.unwrap_or_else(|| env::current_dir().unwrap());
            println!(
                "Vault will be created in parent directory: {:?}",
                parent_path
            );

            print!("Please enter a name for the new vault: ");
            io::stdout().flush()?;
            let mut vault_name = String::new();
            io::stdin().read_line(&mut vault_name)?;
            let vault_name = vault_name.trim();
            if vault_name.is_empty() {
                return Err(CliError::InvalidName(
                    "Vault name cannot be empty.".to_string(),
                ));
            }
            let final_vault_path = parent_path.join(vault_name);
            handle_create_command(&final_vault_path, vault_name)
        }
        TopLevelCommands::Open { path } => {
            let effective_path = path.unwrap_or_else(|| env::current_dir().unwrap());
            println!("Opening vault at: {:?}", effective_path);
            handle_open_command(&effective_path)
        }
    };

    match vault_result {
        Ok(vault) => {
            println!(
                "Vault '{}' is now open. Entering interactive mode.",
                vault.config.name
            );
            println!("Type 'help' for commands or 'exit' to quit.");
            let mut app_state = AppState {
                active_vault: Some(Arc::new(Mutex::new(vault))),
            };
            run_repl(&mut app_state)?;
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
    Ok(())
}

fn handle_create_command(path: &PathBuf, vault_name: &str) -> Result<Vault, CliError> {
    print!("Create an encrypted vault? [Y/n]: ");
    io::stdout().flush()?;
    let mut encrypt_choice = String::new();
    io::stdin().read_line(&mut encrypt_choice)?;

    let password = if encrypt_choice.trim().eq_ignore_ascii_case("y") {
        let pass = rpassword::prompt_password("Enter password for the new vault: ")?;
        let pass_confirm = rpassword::prompt_password("Confirm password: ")?;
        if pass != pass_confirm {
            return Err(CliError::PasswordMismatch);
        }
        Some(pass)
    } else {
        None
    };

    Ok(Vault::create_vault_local(
        path,
        vault_name,
        password.as_deref(),
    )?)
}

fn handle_open_command(path: &PathBuf) -> Result<Vault, CliError> {
    match Vault::open_vault_local(path, None) {
        Ok(vault) => Ok(vault),
        Err(OpenError::PasswordRequired) => {
            println!("This vault is encrypted.");
            let password = rpassword::prompt_password("Enter password: ")?;
            Ok(Vault::open_vault_local(path, Some(&password))?)
        }
        Err(e) => Err(e.into()),
    }
}
