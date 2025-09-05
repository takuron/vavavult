mod cli;
mod utils;
mod handlers;

use std::path::{PathBuf};
use clap::{Parser};
use rustyline::DefaultEditor;
use vavavult::vault::{OpenError, Vault}; // 引入 FileEntry 和 ListResult
use std::error::Error;
use std::{env};
use std::io::{self, Write};
use crate::cli::{Cli, ReplCommand, TopLevelCommands};

// --- AppState 和 CLI/REPL 定义 (不变) ---
struct AppState {
    active_vault: Option<Vault>,
}


// --- main 函数 (不变) ---
fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let vault_result: Result<Vault, Box<dyn Error>> = match cli.command {
        TopLevelCommands::Create { path } => {
            let parent_path = match path {
                Some(p) => p,
                None => env::current_dir()?,
            };
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
            let effective_path = match path {
                Some(p) => p,
                None => env::current_dir()?,
            };
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


// --- `handle_create_command` 和 `handle_open_command` (不变) ---
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


// --- `run_repl` 函数 (核心修改点) ---
fn run_repl(app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    let mut rl = DefaultEditor::new()?;

    loop {
        let prompt = match &app_state.active_vault {
            Some(vault) => format!("vavavult[{}]> ", vault.config.name),
            None => "vavavult(disconnected)> ".to_string(),
        };

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
                        // 将命令处理逻辑移到一个单独的函数中，让 run_repl 更整洁
                        if let Err(e) = handle_repl_command(command, app_state) {
                            eprintln!("Error: {}", e);
                        }
                    },
                    Err(e) => {
                        e.print()?;
                    }
                }
            }
            Err(_) => {
                if let Some(vault) = app_state.active_vault.take() {
                    println!("\nClosing vault '{}'. Goodbye!", vault.config.name);
                }
                break;
            }
        }
        // 在 `handle_repl_command` 中处理 `Exit` 命令后，检查是否应该退出循环
        if app_state.active_vault.is_none() && !is_session_active(app_state) {
            break;
        }
    }
    Ok(())
}

// --- 新增: REPL 命令处理器 ---
fn handle_repl_command(command: ReplCommand, app_state: &mut AppState) -> Result<(), Box<dyn Error>> {
    // 大多数命令都需要一个打开的 vault，我们先检查
    let vault = match &app_state.active_vault {
        Some(v) => v,
        None => {
            // 对于不需要 vault 的命令，我们在这里处理
            return match command {
                ReplCommand::Exit => {
                    println!("Goodbye!");
                    // 设置一个标志来告诉 run_repl 退出
                    set_session_inactive(app_state);
                    Ok(())
                },
                _ => Err("No vault is open. Please use 'open' or 'create' first.".into()),
            };
        }
    };

    match command {
        ReplCommand::Add { local_path, vault_name } => {
            handlers::add::handle_add(vault, &local_path, vault_name)?;
        }
        ReplCommand::List { path, search } => {
            handlers::list::handle_list(vault,path,search)?;
        }
        ReplCommand::Open { vault_name, sha256 } => {
            handlers::open::handle_open(vault,vault_name,sha256)?;
        }
        ReplCommand::Extract { vault_name, sha256, dir_path, destination, output_name, delete } => {
            handlers::extract::handle_extract(vault,vault_name,sha256,dir_path,destination,output_name,delete)?;
        }
        ReplCommand::Remove { vault_name, sha256 } => {
            handlers::remove::handle_remove(vault,vault_name,sha256)?;
        }
        ReplCommand::Status => {
            println!("Active vault: {}", vault.config.name);
            println!("Path: {:?}", vault.root_path);
            println!("Encryption: {:?}", vault.config.encrypt_type);
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



// 模拟会话状态的辅助函数
fn is_session_active(_app_state: &AppState) -> bool {
    // 在这个实现中，只要 vault 关闭了，我们就认为会话结束
    _app_state.active_vault.is_some()
}

fn set_session_inactive(app_state: &mut AppState) {
    // 确保 vault 被 .take()
    app_state.active_vault = None;
}