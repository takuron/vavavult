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
    /// Create a new vault
    //  创建一个新的保险库
    Create {
        /// The parent path where the vault will be created
        //  将在其中创建保险库的父路径
        #[arg(value_name = "PARENT_PATH")]
        path: Option<PathBuf>,
    },
    /// Open an existing vault
    //  打开一个现有的保险库
    Open {
        /// The path to the vault
        //  保险库的路径
        #[arg(value_name = "VAULT_PATH")]
        path: Option<PathBuf>,
    },
}

// --- REPL (Interactive) Commands ---
// --- REPL (交互式) 命令定义 ---
#[derive(Parser, Debug)]
#[command(no_binary_name = true, about = "REPL commands")]
pub enum ReplCommand {
    /// Add a file or directory to the vault
    //  将一个文件或目录添加到保险库
    Add {
        /// The local path of the file or directory to add
        //  要添加的本地文件或目录的路径
        #[arg(required = true)]
        local_path: PathBuf,

        /// (Optional) Specify a new name for the added file (single file only)
        // (可选) 为添加的文件指定一个新名称 (仅限单文件)
        #[arg(short = 'n', long = "name")]
        file_name: Option<String>,

        /// (Optional) Specify the destination directory inside the vault
        // (可选) 指定在保险库中的目标目录
        #[arg(short = 'd', long = "dir")]
        dest_dir: Option<String>,
    },
    /// List files and directories in the vault
    //  列出保险库中的文件和目录
    #[command(visible_alias = "ls")]
    List {
        /// List contents by virtual path
        //  按虚拟路径列出内容
        #[arg(short = 'p', long = "path", group = "list_mode")]
        path: Option<String>,

        /// Fuzzy search for files by keyword
        // 根据关键词模糊搜索文件名
        #[arg(short = 's', long = "search", group = "list_mode")]
        search: Option<String>,

        /// Search for files by tag
        //  根据标签搜索文件
        #[arg(short = 't', long = "tag", group = "list_mode")]
        tag: Option<String>,

        /// Show detailed information for each file
        //  显示每个文件的详细信息
        #[arg(short = 'd', long = "detail")]
        detail: bool,
    },
    /// Open a file from the vault with the default application
    //  使用默认应用程序从保险库中打开一个文件
    Open {
        /// The name of the file to open
        //  要打开的文件的名称
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,
        /// The SHA256 hash of the file to open
        //  要打开的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
    },
    /// Extract a file or directory from the vault
    //  从保险库中提取一个文件或目录
    #[command(visible_alias = "get")]
    Extract {
        /// The name of the file to extract (in the vault)
        //  要提取的文件的名称 (在保险库中)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present_any = ["sha256", "dir_path"])]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to extract
        //  要提取的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,

        /// The vault virtual directory to extract
        //  要提取的保险库虚拟目录
        #[arg(short = 'd', long = "dir", group = "identifier")]
        dir_path: Option<String>,

        /// The local destination directory where the file(s) will be saved
        //  文件将被保存到的本地目标目录
        #[arg(required = true)]
        destination: PathBuf,

        /// (Optional) Specify a new name for the extracted file (single file extraction only)
        //  (可选) 为提取出的文件指定一个新的名称 (仅限单文件提取)
        #[arg(short = 'o', long = "output", conflicts_with = "dir_path")]
        output_name: Option<String>,

        /// Delete the source file from the vault after successful extraction
        //  提取成功后从保险库中删除源文件
        #[arg(long)]
        delete: bool,

        /// Recursively extract all files in subdirectories (directory mode only)
        //  递归提取子目录中的所有文件 (仅限目录模式)
        #[arg(short = 'r', long, requires = "dir_path")]
        recursive: bool,
    },
    /// Permanently delete a file from the vault
    // 从保险库中永久删除一个文件
    #[command(visible_alias = "rm")]
    Remove {
        /// The name of the file to delete
        //  要删除的文件的名称
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,
        /// The SHA256 hash of the file to delete
        //  要删除的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
    },
    /// Rename the current vault
    //  重命名当前保险库
    Rename {
        /// The new name for the vault
        //  保险库的新名称
        #[arg(required = true)]
        new_name: String,
    },
    /// Manage tags for files
    //  管理文件标签
    #[command(subcommand)]
    Tag(TagCommand),
    /// Show the status of the current vault
    //  显示当前保险库的状态
    Status,
    /// Close the current vault
    //  关闭当前保险库
    Close,
    /// Exit the interactive session
    //  退出交互式会话
    Exit,
}

// --- Subcommands for `tag` ---
// --- `tag` 的子命令 ---
#[derive(Parser, Debug)]
pub enum TagCommand {
    /// Add one or more tags to a file or a directory of files
    //  将一个或多个标签添加到一个文件或文件目录
    Add {
        /// The name of the file to tag (in the vault)
        //  要标记的文件的名称 (在保险库中)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present_any = ["sha256", "dir_path"])]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to tag
        //  要标记的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,

        /// The vault directory to apply tags to (batch mode)
        //  要应用标签的保险库目录 (批处理模式)
        #[arg(short = 'd', long = "dir", group = "identifier")]
        dir_path: Option<String>,

        /// One or more tags to add, separated by spaces
        //  要添加的一个或多个标签，以空格分隔
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,

        /// Recursively add tags to all files in subdirectories (directory mode only)
        //  递归地为子目录中的所有文件添加标签 (仅限目录模式)
        #[arg(short = 'r', long, requires = "dir_path")]
        recursive: bool,
    },
    /// Remove one or more tags from a file or a directory of files
    //  从一个文件或文件目录中删除一个或多个标签
    Remove {
        /// The name of the file to remove tags from (in the vault)
        //  要从中删除标签的文件的名称 (在保险库中)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present_any = ["sha256", "dir_path"])]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to remove tags from
        //  要从中删除标签的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,

        /// The vault directory to remove tags from (batch mode)
        //  要从中删除标签的保险库目录 (批处理模式)
        #[arg(short = 'd', long = "dir", group = "identifier")]
        dir_path: Option<String>,

        /// One or more tags to remove, separated by spaces
        //  要删除的一个或多个标签，以空格分隔
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,

        /// Recursively remove tags from all files in subdirectories (directory mode only)
        //  递归地从子目录中的所有文件中删除标签 (仅限目录模式)
        #[arg(short = 'r', long, requires = "dir_path")]
        recursive: bool,
    },
    /// Clear all tags from a file
    //  清除一个文件的所有标签
    Clear {
        /// The name of the file to clear tags from (in the vault)
        //  要清除标签的文件的名称 (在保险库中)
        #[arg(short = 'n', long = "name", group = "identifier", required_unless_present = "sha256")]
        vault_name: Option<String>,

        /// The SHA256 hash of the file to clear tags from
        //  要清除标签的文件的 SHA256 哈希值
        #[arg(short = 's', long = "sha256", group = "identifier")]
        sha256: Option<String>,
    },
}