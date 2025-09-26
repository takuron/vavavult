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
use crate::cli::{Cli, ReplCommand, TagCommand, TopLevelCommands};

struct AppState {
    active_vault: Option<Vault>,
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
            let mut app_state = AppState { active_vault: Some(vault) };
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
    Ok(Vault::create_vault(path, vault_name, password.as_deref())?)
}

fn handle_open_command(path: &PathBuf) -> Result<Vault, Box<dyn Error>> {
    match Vault::open_vault(path, None) {
        Ok(vault) => Ok(vault),
        Err(OpenError::PasswordRequired) => {
            println!("This vault is encrypted.");
            let password = rpassword::prompt_password("Enter password: ")?;
            Ok(Vault::open_vault(path, Some(&password))?)
        }
        Err(e) => Err(e.into()),
    }
}

fn run_repl(app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    let mut rl = DefaultEditor::new()?;

    // 循环条件: 只要 active_vault 不为 None，就继续
    while let Some(vault) = &app_state.active_vault {
        let prompt = format!("vavavult[{}]> ", vault.config.name);

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
                if let Some(vault) = app_state.active_vault.take() {
                    println!("\nClosing vault '{}'. Goodbye!", vault.config.name);
                }
                break; // 明确退出循环
            }
        }
    }
    Ok(())
}


/// REPL 命令处理器
fn handle_repl_command(command: ReplCommand, app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    // 检查 vault 是否存在。如果命令是 Exit 或 Close，它们会使 active_vault 变为 None，
    // 从而自然地终止 run_repl 中的 while let 循环。
    let Some(vault) = app_state.active_vault.as_mut() else {
        // 如果 vault 已经是 None，说明会话已结束，不应再处理任何命令。
        return Ok(());
    };

    match command {
        ReplCommand::Add { local_path, file_name, dest_dir } => {
            handlers::add::handle_add(vault, &local_path, file_name, dest_dir)?;
        }
        ReplCommand::List { path, search, tag, detail } => {
            handlers::list::handle_list(vault, path, search, tag, detail)?; // <-- 传递 tag
        }
        ReplCommand::Open { vault_name, sha256 } => {
            // open 是只读操作
            handlers::open::handle_open(vault, vault_name, sha256)?;
        }
        ReplCommand::Extract { vault_name, sha256, dir_path, destination, output_name, delete, recursive } => {
            handlers::extract::handle_extract(vault, vault_name, sha256, dir_path, destination, output_name, delete, recursive)?;
        }
        ReplCommand::Remove { vault_name, sha256 } => {
            handlers::remove::handle_remove(vault, vault_name, sha256)?;
        }
        ReplCommand::Status => {
            handlers::status::handle_status(vault)?;
        }
        ReplCommand::Rename { new_name } => { // <-- 添加这个匹配分支
            handlers::rename::handle_rename(vault, &new_name)?;
        }
        // --- 修改 Tag 命令的处理逻辑 ---
        ReplCommand::Tag(tag_command) => {
            match tag_command {
                TagCommand::Add { vault_name, sha256, dir_path, tags, recursive } => {
                    handlers::tag::handle_tag_add(vault, vault_name, sha256, dir_path, &tags, recursive)?;
                }
                TagCommand::Remove { vault_name, sha256, dir_path, tags, recursive } => {
                    handlers::tag::handle_tag_remove(vault, vault_name, sha256, dir_path, &tags, recursive)?;
                }
                TagCommand::Clear { vault_name, sha256 } => {
                    handlers::tag::handle_tag_clear(vault, vault_name, sha256)?;
                }
            }
        }
        ReplCommand::Close => {
            let vault_name = app_state.active_vault.take().unwrap().config.name;
            println!("Closed vault '{}'.", vault_name);
        }
        ReplCommand::Exit => {
            let vault_name = app_state.active_vault.take().unwrap().config.name;
            println!("Closing vault '{}'. Goodbye!", vault_name);
        }
    }
    Ok(())
}