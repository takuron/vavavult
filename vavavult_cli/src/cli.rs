use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: crate::TopLevelCommands,
}

#[derive(Subcommand, Debug)]
pub enum TopLevelCommands {
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
pub enum ReplCommand {
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
    #[command(visible_alias = "ls")]
    List {
        /// 按虚拟路径列出内容
        #[arg(short = 'p', long = "path", group = "list_mode")]
        path: Option<String>,

        /// 根据关键词模糊搜索文件名
        #[arg(short = 's', long = "search", group = "list_mode")]
        search: Option<String>,

        /// 根据标签搜索文件
        #[arg(short = 't', long = "tag", group = "list_mode")] // <-- 添加这个新标志
        tag: Option<String>,

        /// 显示每个文件的详细信息
        #[arg(short = 'd', long = "detail")] // <-- 添加这个新标志
        detail: bool,
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

        /// 递归提取子目录中的所有文件 (仅限目录模式)
        #[arg(short = 'r', long, requires = "dir_path")] // <-- 为 Extract 添加
        recursive: bool,
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
    /// 重命名当前保险库
    Rename {
        /// 保险库的新名称
        #[arg(required = true)]
        new_name: String,
    },
    /// Manage tags for files (管理文件标签)
    #[command(subcommand)] // <-- 告诉 clap, `Tag` 有子命令
    Tag(TagCommand),       // <-- 将之前的实现包裹在新枚举中
    /// 显示当前保险库的状态
    Status,
    /// 关闭当前保险库
    Close,
    /// 退出交互式会话
    Exit,
}

// --- 新增：为 `tag` 创建一个子命令枚举 ---
#[derive(Parser, Debug)]
pub enum TagCommand {
    /// Add one or more tags to a file or a directory of files
    Add {
        /// The name of the file to tag (in the vault)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present_any = ["sha256", "dir_path"])]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to tag
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,

        /// The vault directory to apply tags to recursively (batch mode)
        #[arg(short = 'd', long = "dir", group = "identifier")]
        dir_path: Option<String>,

        /// One or more tags to add, separated by spaces
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,

        /// 递归地为子目录中的所有文件添加标签 (仅限目录模式)
        #[arg(short = 'r', long, requires = "dir_path")] // <-- 为 Tag Add 添加
        recursive: bool,
    },
    Remove {
        /// The name of the file to remove tags from (in the vault)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present_any = ["sha256", "dir_path"])]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to remove tags from
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,

        /// The vault directory to remove tags from recursively (batch mode)
        #[arg(short = 'd', long = "dir", group = "identifier")]
        dir_path: Option<String>,

        /// One or more tags to remove, separated by spaces
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,

        /// 递归地为子目录中的所有文件添加标签 (仅限目录模式)
        #[arg(short = 'r', long, requires = "dir_path")] // <-- 为 Tag Add 添加
        recursive: bool,
    },
    Clear {
        /// The name of the file to clear tags from (in the vault)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to clear tags from
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
    },
}