use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;
use vavavult::vault::{OpenError, Vault, FileEntry, ListResult, QueryResult}; // 引入 FileEntry 和 ListResult
use std::error::Error;
use std::env;
use std::io::{self, Write};

// --- AppState 和 CLI/REPL 定义 (不变) ---
struct AppState {
    active_vault: Option<Vault>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommands,
}

#[derive(Subcommand, Debug)]
enum TopLevelCommands {
    Create {
        #[arg(value_name = "PARENT_PATH")]
        path: Option<PathBuf>,
    },
    Open {
        #[arg(value_name = "VAULT_PATH")]
        path: Option<PathBuf>,
    },
}

// --- REPL (交互式) 命令定义 (核心修改点) ---
#[derive(Parser, Debug)]
#[command(no_binary_name = true, about = "REPL commands")]
enum ReplCommand {
    /// 将一个文件添加到保险库
    Add {
        #[arg(required = true)]
        local_path: PathBuf,
        #[arg(short = 'n', long = "name")]
        vault_name: Option<String>,
    },
    /// 列出保险库中的文件和目录
    #[command(visible_alias = "ls")] // 我们可以为 list 添加一个别名 `ls`
    List {
        /// 按虚拟路径列出内容
        #[arg(short = 'p', long = "path", group = "list_mode")]
        path: Option<String>,

        /// 根据关键词模糊搜索文件名
        #[arg(short = 's', long = "search", group = "list_mode")]
        search: Option<String>,
    },
    Extract {
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
        #[arg(required = true)]
        destination: PathBuf,
        #[arg(short = 'o', long = "output")]
        output_name: Option<String>,
        /// 提取成功后从保险库中删除该文件
        #[arg(long)]
        delete: bool,
    },
    /// 从保险库中永久删除一个文件
    #[command(visible_alias = "rm")]
    Remove {
        /// 要删除的文件的名称
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,
        /// 要删除的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
    },
    /// 显示当前保险库的状态
    Status,
    /// 关闭当前保险库
    Close,
    /// 退出交互式会话
    Exit,
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
            println!("Adding file {:?}...", local_path);
            match vault.add_file(&local_path, vault_name.as_deref()) {
                Ok(hash) => println!("Successfully added file. Hash: {}", hash),
                Err(e) => eprintln!("Error adding file: {}", e),
            }
        }
        ReplCommand::List { path, search } => {
            match (path, search) {
                // 模式 1: list -s <keyword>
                (None, Some(keyword)) => {
                    let files = vault.find_by_name_fuzzy(&keyword)?;
                    println!("Found {} file(s) matching '{}':", files.len(), keyword);
                    print_file_entries(&files);
                }
                // 模式 2: list -p <path>
                (Some(p), None) => {
                    let result = vault.list_by_path(&p)?;
                    println!("Contents of '{}':", p);
                    print_list_result(&result);
                }
                // 模式 3: list (无参数)
                (None, None) => {
                    let files = vault.list_all()?;
                    println!("All {} file(s) in the vault:", files.len());
                    print_file_entries(&files);
                }
                // clap 的 group 功能会阻止这种情况发生，但 match 需要它是详尽的
                (Some(_), Some(_)) => unreachable!(),
            }
        }
        ReplCommand::Extract { vault_name, sha256, destination, output_name, delete } => {
            let file_entry = find_file_entry(vault, vault_name, sha256)?;
            let final_path = determine_output_path(&file_entry, destination, output_name);

            if delete {
                if !confirm_action(&format!(
                    "This will extract '{}' to {:?} and then PERMANENTLY DELETE it. Are you sure?",
                    file_entry.name, final_path
                ))? {
                    println!("Operation cancelled.");
                    return Ok(());
                }
            }

            println!("Extracting '{}' to {:?}...", file_entry.name, final_path);
            vault.extract_file(&file_entry.sha256sum, &final_path)?;
            println!("File extracted successfully.");

            if delete {
                println!("Deleting '{}' from vault...", file_entry.name);
                vault.remove_file(&file_entry.sha256sum)?;
                println!("File successfully deleted from vault.");
            }
        }
        ReplCommand::Remove { vault_name, sha256 } => {
            let file_entry = find_file_entry(vault, vault_name, sha256)?;

            if !confirm_action(&format!(
                "Are you sure you want to PERMANENTLY DELETE '{}'?",
                file_entry.name
            ))? {
                println!("Operation cancelled.");
                return Ok(());
            }

            println!("Deleting '{}' from vault...", file_entry.name);
            vault.remove_file(&file_entry.sha256sum)?;
            println!("File successfully deleted.");
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

// --- 新增: 格式化输出的辅助函数 ---

/// 打印 `FileEntry` 列表的辅助函数
fn print_file_entries(files: &[FileEntry]) {
    if files.is_empty() {
        return;
    }
    // 调整列的顺序和宽度
    println!("{:<60} {:<30} {}", "Name", "Tags", "SHA256 (short)");
    println!("{}", "-".repeat(120));
    for entry in files {
        let short_hash = &entry.sha256sum[..12];
        let tags = if entry.tags.is_empty() {
            "-".to_string()
        } else {
            entry.tags.join(", ")
        };
        // 调整变量的打印顺序
        println!("{:<60} {:<30} {}", entry.name, tags, short_hash);
    }
}


// --- 新增: 辅助函数 ---

/// 根据 name 或 sha256 查找文件，返回找到的 FileEntry
fn find_file_entry(vault: &Vault, name: Option<String>, sha: Option<String>) -> Result<FileEntry, Box<dyn Error>> {
    let query_result = if let Some(n) = name {
        vault.find_by_name(&n)?
    } else if let Some(s) = sha {
        vault.find_by_hash(&s)?
    } else {
        unreachable!(); // Clap 应该已经阻止了这种情况
    };

    match query_result {
        QueryResult::Found(entry) => Ok(entry),
        QueryResult::NotFound => Err("File not found in the vault.".into()),
    }
}

/// 确定最终的输出路径
fn determine_output_path(entry: &FileEntry, dest_dir: PathBuf, output_name: Option<String>) -> PathBuf {
    let final_filename = output_name.unwrap_or_else(|| {
        Path::new(&entry.name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed_file")
            .to_string()
    });
    dest_dir.join(final_filename)
}

/// 向用户请求确认破坏性操作
fn confirm_action(prompt: &str) -> Result<bool, io::Error> {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    Ok(confirmation.trim().eq_ignore_ascii_case("y") || confirmation.trim().eq_ignore_ascii_case("yes"))
}

/// 打印 `ListResult` 的辅助函数
fn print_list_result(result: &ListResult) {
    if result.subdirectories.is_empty() && result.files.is_empty() {
        println!("(empty)");
        return;
    }
    // 先打印目录
    for dir in &result.subdirectories {
        println!("[{}/]", dir);
    }
    // 再打印文件
    print_file_entries(&result.files);
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