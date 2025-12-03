mod cli;
mod utils;
mod handlers;

use std::path::{PathBuf};
use clap::{Parser};
use rustyline::DefaultEditor;
use vavavult::vault::{OpenError, Vault};
use std::error::Error;
use std::{env};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use crate::cli::{Cli, ReplCommand, TagCommand, TopLevelCommands, VaultCommand};

struct AppState {
    // --- 修改: 将 Vault 包装在 Arc<Mutex<>> 中 ---
    active_vault: Option<Arc<Mutex<Vault>>>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let vault_result: Result<Vault, Box<dyn Error>> = match cli.command {
        TopLevelCommands::Create { path } => {
            let parent_path = path.unwrap_or_else(|| env::current_dir().unwrap());
            println!("Vault will be created in parent directory: {:?}", parent_path);

            print!("Please enter a name for the new vault: ");
            io::stdout().flush()?;
            let mut vault_name = String::new();
            io::stdin().read_line(&mut vault_name)?;
            let vault_name = vault_name.trim();
            if vault_name.is_empty() {
                return Err("Vault name cannot be empty.".into());
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
            println!("Vault '{}' is now open. Entering interactive mode.", vault.config.name);
            println!("Type 'help' for commands or 'exit' to quit.");
            let mut app_state = AppState { active_vault: Some(Arc::new(Mutex::new(vault))) };
            run_repl(&mut app_state)?;
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
    Ok(())
}

fn handle_create_command(path: &PathBuf, vault_name: &str) -> Result<Vault, Box<dyn Error>> {
    print!("Create an encrypted vault? [Y/n]: ");
    io::stdout().flush()?;
    let mut encrypt_choice = String::new();
    io::stdin().read_line(&mut encrypt_choice)?;

    let password = if encrypt_choice.trim().eq_ignore_ascii_case("y") {
        let pass = rpassword::prompt_password("Enter password for the new vault: ")?;
        let pass_confirm = rpassword::prompt_password("Confirm password: ")?;
        if pass != pass_confirm {
            return Err("Passwords do not match.".into());
        }
        Some(pass)
    } else {
        None
    };

    Ok(Vault::create_vault_local(path, vault_name, password.as_deref())?)
}

fn handle_open_command(path: &PathBuf) -> Result<Vault, Box<dyn Error>> {
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

fn run_repl(app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    let mut rl = DefaultEditor::new()?;

    // 循环条件: 只要 active_vault 不为 None，就继续
    while let Some(vault_arc) = &app_state.active_vault {
        let vault_name = vault_arc.lock().unwrap().config.name.clone();
        let prompt = format!("vavavult[{}]> ", vault_name);

        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;
                let args = shlex::split(line.as_str()).unwrap_or_default();
                if args.is_empty() {
                    continue;
                }

                match ReplCommand::try_parse_from(args) {
                    Ok(command) => {
                        if let Err(e) = handle_repl_command(command, app_state) {
                            eprintln!("Error: {}", e);
                        }
                    },
                    Err(e) => {
                        e.print()?;
                    }
                }
            }
            Err(_) => { // Handles Ctrl-C or Ctrl-D
                if let Some(vault_arc) = app_state.active_vault.take() {
                    let vault_name = vault_arc.lock().unwrap().config.name.clone();
                    println!("\nClosing vault '{}'. Goodbye!", vault_name);
                }
                break;
            }
        }
    }
    Ok(())
}


/// REPL 命令处理器
fn handle_repl_command(command: ReplCommand, app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    // 检查 vault 是否存在。如果命令是 Exit 或 Close，它们会使 active_vault 变为 None，
    // 从而自然地终止 run_repl 中的 while let 循环。
    let Some(vault_arc) = app_state.active_vault.as_mut() else {
        return Ok(());
    };

    match command {
        ReplCommand::Add { local_path, path, name, parallel } => {
            handlers::add::handle_add(Arc::clone(vault_arc), &local_path, path, name, parallel)?;
        }
        ReplCommand::List { path, long, recursive } => {
            let vault = vault_arc.lock().unwrap();
            handlers::list::handle_list(&vault, path, long, recursive)?;
        }
        ReplCommand::Search { keyword, long } => {
            let vault = vault_arc.lock().unwrap();
            handlers::search::handle_search(&vault, &keyword, long)?;
        }
        ReplCommand::Open { path, hash } => {
            let vault = vault_arc.lock().unwrap();
            // 传递新的参数
            handlers::open::handle_open(&vault, path, hash)?;
        }
        ReplCommand::Extract { path, hash, destination, output_name, non_recursive, delete, parallel } => {
            handlers::extract::handle_extract(
                Arc::clone(vault_arc),
                path,
                hash,
                destination,
                output_name,
                non_recursive,
                delete,
                parallel
            )?;
        }
        ReplCommand::Remove { path, hash, recursive, force } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::remove::handle_remove(&mut vault, path, hash, recursive, force)?;
        }
        ReplCommand::Move { path, hash, destination } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::move_cl::handle_move(&mut vault, path, hash, destination)?;
        }
        ReplCommand::Rename { path, hash, new_name } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::rename::handle_file_rename(&mut vault, path, hash, &new_name)?;
        }
        ReplCommand::Vault(vault_command) => {
            match vault_command {
                VaultCommand::Rename { new_name } => {
                    let mut vault = vault_arc.lock().unwrap();

                    handlers::vault::handle_vault_rename(&mut vault, &new_name)?;
                }
                VaultCommand::Status => {
                    let vault = vault_arc.lock().unwrap();
                    handlers::vault::handle_status(&vault)?;
                }
                // 未来可以处理 VaultCommand 的其他变体
            }
        }
        // --- 修改 Tag 命令的处理逻辑 ---
        ReplCommand::Tag(tag_command) => {
            let mut vault = vault_arc.lock().unwrap();
            match tag_command {
                TagCommand::Add { path, hash, tags } => {
                    handlers::tag::handle_tag_add(&mut vault, path, hash, &tags)?;
                }
                TagCommand::Remove { path, hash, tags } => {
                    handlers::tag::handle_tag_remove(&mut vault, path, hash, &tags)?;
                }
                TagCommand::Clear { path, hash } => {
                    handlers::tag::handle_tag_clear(&mut vault, path, hash)?;
                }
                TagCommand::Color { path, hash, color } => {
                    handlers::tag::handle_tag_color(&mut vault, path, hash, &color)?;
                }
            }
        }
        ReplCommand::Exit => {
            let vault_name = app_state.active_vault.take().unwrap().lock().unwrap().config.name.clone();
            println!("Closing vault '{}'. Goodbye!", vault_name);
        }
    }
    Ok(())
}