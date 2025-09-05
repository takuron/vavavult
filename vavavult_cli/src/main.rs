use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use rustyline::DefaultEditor;
use vavavult::vault::{OpenError, Vault, FileEntry, ListResult, QueryResult}; // 引入 FileEntry 和 ListResult
use std::error::Error;
use std::{env, fs};
use std::io::{self, Write};
use walkdir::WalkDir;

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
        /// 要添加的本地文件或目录的路径
        #[arg(required = true)]
        local_path: PathBuf,

        /// 在保险库中为文件设置一个自定义名称 (对于目录，则作为名称前缀)
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
    Open {
        /// 要打开的文件的名称
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,
        /// 要打开的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
    },
    #[command(visible_alias = "get")]
    Extract {
        /// 要提取的文件的名称 (在保险库中)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present_any = ["sha256", "dir_path"])]
        vault_name: Option<String>,

        /// 要提取的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,

        /// 要提取的保险库虚拟目录 (会递归提取所有文件)
        #[arg(short = 'd', long = "dir", group = "identifier")]
        dir_path: Option<String>,

        /// 文件将被保存到的本地目标目录
        #[arg(required = true)]
        destination: PathBuf,

        /// (可选) 为提取出的文件指定一个新的名称 (仅限单文件提取)
        #[arg(short = 'o', long = "output", conflicts_with = "dir_path")]
        output_name: Option<String>,

        /// 提取成功后从保险库中删除源文件
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
            if !local_path.exists() {
                return Err(format!("Path does not exist: {:?}", local_path).into());
            }

            // --- 新逻辑：区分文件和目录 ---
            if local_path.is_dir() {
                handle_add_directory(vault, &local_path, vault_name)?;
            } else {
                handle_add_file(vault, &local_path, vault_name)?;
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
        ReplCommand::Open { vault_name, sha256 } => {
            let file_entry = find_file_entry(vault, vault_name, sha256)?;

            // 1. 创建一个临时文件路径
            let temp_dir = env::temp_dir();
            let file_name = Path::new(&file_entry.name).file_name().unwrap_or_default();
            let temp_path = temp_dir.join(file_name);

            // 2. 提取文件到临时路径
            println!("Extracting a temporary copy to {:?}...", temp_path);
            vault.extract_file(&file_entry.sha256sum, &temp_path)?;

            // 3. 使用 opener 打开文件
            match opener::open(&temp_path) {
                Ok(_) => {
                    println!("Successfully opened '{}'.", file_entry.name);
                    println!("NOTE: You are viewing a temporary copy. Any changes will NOT be saved to the vault.");
                }
                Err(e) => {
                    eprintln!("Failed to open file with default application: {}", e);
                }
            }
        }
        ReplCommand::Extract { vault_name, sha256, dir_path, destination, output_name, delete } => {
            if let Some(dir) = dir_path {
                // 新增：处理目录提取
                handle_extract_directory(vault, &dir, &destination, delete)?;
            } else {
                // 现有：处理单文件提取
                handle_extract_single_file(vault, vault_name, sha256, &destination, output_name, delete)?;
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

/// 处理添加单个文件的逻辑
fn handle_add_file(vault: &Vault, local_path: &Path, vault_name: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Adding file {:?}...", local_path);
    match vault.add_file(local_path, vault_name.as_deref()) {
        Ok(hash) => println!("Successfully added file. Hash: {}", hash),
        Err(e) => eprintln!("Error adding file: {}", e),
    }
    Ok(())
}

/// 处理批量添加目录的逻辑
fn handle_add_directory(vault: &Vault, local_path: &Path, prefix: Option<String>) -> Result<(), Box<dyn Error>> {
    println!("Scanning directory {:?}...", local_path);

    // 1. 收集所有待添加的文件
    let mut files_to_add = Vec::new();
    for entry in WalkDir::new(local_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let source_path = entry.into_path();
            // 计算文件相对于根目录的路径
            let relative_path = source_path.strip_prefix(local_path)?.to_path_buf();

            // 构建在 vault 中的目标路径
            let vault_target_path = if let Some(p) = &prefix {
                // 如果有前缀，则拼接
                Path::new(p).join(&relative_path)
            } else {
                // 否则直接使用相对路径
                relative_path
            };

            files_to_add.push((source_path, vault_target_path));
        }
    }

    if files_to_add.is_empty() {
        println!("No files found to add in the directory.");
        return Ok(());
    }

    // 2. 向用户展示并请求确认
    println!("The following {} files will be added:", files_to_add.len());
    for (source, target) in &files_to_add {
        println!("  - {:?} -> {}", source, target.display());
    }
    if !confirm_action("Do you want to proceed with adding these files?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    // 3. 执行添加
    let mut success_count = 0;
    let mut fail_count = 0;
    for (source, target) in files_to_add {
        print!("Adding {:?}...", source);
        io::stdout().flush()?;
        match vault.add_file(&source, target.to_str()) {
            Ok(_) => {
                println!(" OK");
                success_count += 1;
            }
            Err(e) => {
                println!(" FAILED ({})", e);
                fail_count += 1;
            }
        }
    }

    println!("\nBatch add complete. {} succeeded, {} failed.", success_count, fail_count);
    Ok(())
}

/// 处理提取单个文件的逻辑
fn handle_extract_single_file(vault: &Vault, vault_name: Option<String>, sha256: Option<String>, destination: &Path, output_name: Option<String>, delete: bool) -> Result<(), Box<dyn Error>> {
    let file_entry = find_file_entry(vault, vault_name, sha256)?;
    let final_path = determine_output_path(&file_entry, destination.to_path_buf(), output_name);

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
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }
    vault.extract_file(&file_entry.sha256sum, &final_path)?;
    println!("File extracted successfully.");

    if delete {
        println!("Deleting '{}' from vault...", file_entry.name);
        vault.remove_file(&file_entry.sha256sum)?;
        println!("File successfully deleted from vault.");
    }
    Ok(())
}

/// 处理提取整个目录的逻辑
fn handle_extract_directory(vault: &Vault, dir_path: &str, destination: &Path, delete: bool) -> Result<(), Box<dyn Error>> {
    println!("Scanning vault directory '{}' for extraction...", dir_path);
    let files_to_extract = get_all_files_recursively(vault, dir_path)?;

    if files_to_extract.is_empty() {
        println!("No files found in vault directory '{}'.", dir_path);
        return Ok(());
    }

    println!("The following {} files will be extracted to {:?}", files_to_extract.len(), destination);
    if delete {
        println!("WARNING: The original files will be PERMANENTLY DELETED from the vault after extraction.");
    }
    if !confirm_action("Do you want to proceed?")? {
        println!("Operation cancelled.");
        return Ok(());
    }

    let mut success_count = 0;
    let mut fail_count = 0;
    for entry in &files_to_extract {
        let relative_path = Path::new(&entry.name).strip_prefix(dir_path).unwrap_or(Path::new(&entry.name));
        let final_path = destination.join(relative_path);

        print!("Extracting {} -> {:?} ...", entry.name, final_path);
        io::stdout().flush()?;

        if let Some(parent) = final_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                println!(" FAILED (could not create local directory: {})", e);
                fail_count += 1;
                continue;
            }
        }

        match vault.extract_file(&entry.sha256sum, &final_path) {
            Ok(_) => {
                println!(" OK");
                success_count += 1;
            }
            Err(e) => {
                println!(" FAILED ({})", e);
                fail_count += 1;
            }
        }
    }

    println!("\nExtraction complete. {} succeeded, {} failed.", success_count, fail_count);

    if delete && success_count > 0 {
        println!("\nDeleting {} extracted files from vault...", success_count);
        if !confirm_action("Confirm deletion of successfully extracted files?")? {
            println!("Deletion cancelled.");
            return Ok(());
        }
        for entry in files_to_extract.iter().filter(|_| fail_count == 0) { // Simple filter for now
            match vault.remove_file(&entry.sha256sum) {
                Ok(_) => println!("Deleted {}.", entry.name),
                Err(e) => eprintln!("Failed to delete {}: {}", entry.name, e),
            }
        }
    }

    Ok(())
}

/// 递归地获取一个 vault 目录下的所有文件
fn get_all_files_recursively(vault: &Vault, dir_path: &str) -> Result<Vec<FileEntry>, Box<dyn Error>> {
    let mut all_files = Vec::new();
    let mut dirs_to_scan = vec![dir_path.to_string()];

    while let Some(current_dir) = dirs_to_scan.pop() {
        let result = vault.list_by_path(&current_dir)?;
        all_files.extend(result.files);
        for subdir in result.subdirectories {
            let full_subdir_path = Path::new(&current_dir).join(subdir).to_string_lossy().into_owned();
            dirs_to_scan.push(full_subdir_path);
        }
    }
    Ok(all_files)
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