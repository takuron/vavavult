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

        /// (Optional) Set the target path or directory in the vault.
        // (可选) 在保险库中设置目标路径或目录。
        #[arg(short = 'p', long = "path")]
        path: Option<String>,

        /// (Optional) Set/override the final filename.
        // (可选) 设置或覆盖最终的文件名。
        #[arg(short = 'n', long = "name")]
        name: Option<String>,

        /// (EXPERIMENTAL) Use multiple threads to add files in parallel
        // (实验性) 使用多线程并行添加文件
        #[arg(long)]
        parallel: bool,
    },
    /// List files and directories in the vault
    //  列出保险库中的文件和目录
    #[command(visible_alias = "ls")]
    List {
        /// (Optional) The vault path to list. Defaults to root ("/") if not provided.
        // (可选) 要列出的保险库路径。如果未提供，则默认为根目录 ("/")。
        #[arg(value_name = "VAULT_PATH")] // [V2 修改] 移除 group = "list_mode"
        path: Option<String>,

        /// Use long-listing format (show details).
        //  使用长列表格式 (显示详细信息)。
        #[arg(short = 'l', long = "long")]
        long: bool,

        /// List subdirectories recursively.
        //  递归列出子目录。
        #[arg(short = 'R', long = "recursive")]
        recursive: bool,
    },
    /// Search for files by keyword
    //  按关键字搜索文件
    #[command(visible_alias = "find")]
    Search {
        /// The keyword to search for in file paths and tags
        //  要在文件路径和标签中搜索的关键字
        #[arg(required = true)]
        keyword: String,

        /// Use long-listing format (show details)
        //  使用长列表格式 (显示详细信息)
        #[arg(short = 'l', long = "long")]
        long: bool,
    },
    /// Open a file from the vault with the default application
    //  使用默认应用程序从保险库中打开一个文件
    Open {
        /// The path of the file to open (e.g., "/report.txt").
        /// Mutually exclusive with --hash.
        //  要打开的文件的路径 (例如 "/report.txt")。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to open.
        /// Mutually exclusive with --path.
        //  要打开的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,
    },

    /// Extract a file or directory from the vault
    //  从保险库中提取一个文件或目录
    #[command(visible_alias = "get")]
    Extract {
        /// The path in the vault to extract (e.g., "/docs/" or "/report.txt").
        /// Mutually exclusive with --hash.
        //  要提取的保险库内路径 (例如 "/docs/" 或 "/report.txt")。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to extract.
        /// Mutually exclusive with --path.
        //  要提取的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// The local destination directory where the file(s) will be saved.
        //  文件将被保存到的本地目标目录。
        #[arg(value_name = "LOCAL_DESTINATION", required = true)]
        destination: PathBuf,

        /// (Optional) Specify a new name for the extracted file.
        /// Only valid when extracting a single file (using --hash or a file path).
        // (可选) 为提取出的文件指定一个新的名称。
        //  仅在提取单个文件时 (使用 --hash 或文件路径) 有效。
        #[arg(short = 'o', long = "output")]
        output_name: Option<String>,

        /// Only extract files directly in the specified directory, not subdirectories.
        /// (The default is to extract recursively).
        //  仅提取指定目录中的直接文件，不提取子目录。
        // （默认行为是递归提取）。
        #[arg(long)]
        non_recursive: bool,

        /// Delete the source file(s) from the vault after successful extraction.
        //  提取成功后从保险库中删除源文件。
        #[arg(long)]
        delete: bool,

        /// (EXPERIMENTAL) Use multiple threads to extract files in parallel.
        // (实验性) 使用多线程并行提取文件。
        #[arg(long)]
        parallel: bool,
    },
    /// Permanently delete a file or directory from the vault
    //  从保险库中永久删除一个文件或目录
    #[command(visible_alias = "rm")]
    Remove {
        /// The path in the vault to delete (e.g., "/docs/" or "/report.txt").
        /// Mutually exclusive with --hash.
        //  要删除的保险库内路径 (例如 "/docs/" 或 "/report.txt")。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to delete.
        /// Mutually exclusive with --path.
        //  要删除的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// Required to delete a directory (only applies when using --path)
        //  删除目录时需要此选项 (仅在使用 --path 时适用)
        #[arg(short = 'r', long)]
        recursive: bool,

        /// Force deletion without confirmation
        //  强制删除而不进行确认
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Move (mv) or rename a file within the vault
    //  在保险库中移动 (mv) 或重命名一个文件
    #[command(visible_alias = "mv")]
    Move {
        /// The path of the file to move.
        //  要移动的文件的路径。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to move.
        //  要移动的文件的完整 43 字符哈希。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// The new destination.
        //  新的目标位置。
        #[arg(required = true, value_name = "DESTINATION")]
        destination: String,
    },

    /// Rename a file in its current directory (in-place)
    //  在当前目录中就地重命名一个文件
    #[command(visible_alias = "ren")]
    Rename {
        /// The path of the file to rename.
        //  要重命名的文件的路径。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to rename.
        //  要重命名的文件的完整 43 字符哈希。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// The new filename (must not contain path separators '/')
        //  新的文件名 (不能包含路径分隔符 '/')
        #[arg(required = true, value_name = "NEW_FILENAME")]
        new_name: String,
    },
    /// Manage tags for files
    //  管理文件标签
    #[command(subcommand)]
    Tag(TagCommand),
    /// Manage the vault itself
    //  管理保险库本身
    #[command(subcommand)]
    Vault(VaultCommand), // 将之前的 Rename 移到这里
    /// Exit the interactive session
    //  退出交互式会话
    Exit,
}

// --- Vault 级别的子命令 ---
#[derive(Parser, Debug)]
pub enum VaultCommand {
    /// Rename the current vault
    //  重命名当前保险库
    Rename {
        /// The new name for the vault
        //  保险库的新名称
        #[arg(required = true)]
        new_name: String,
    },
    Status,
    // 未来可以添加其他 vault 级别的命令, 例如修改密码等
}

// --- Subcommands for `tag` ---
// --- `tag` 的子命令 ---
#[derive(Parser, Debug)]
pub enum TagCommand {
    /// Add one or more tags to a file or directory
    //  将一个或多个标签添加到一个文件或目录
    Add {
        /// The path in the vault to tag (e.g., "/docs/" or "/report.txt").
        /// Mutually exclusive with --hash.
        //  要标记的保险库内路径 (例如 "/docs/" 或 "/report.txt")。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to tag.
        /// Mutually exclusive with --path.
        //  要标记的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// One or more tags to add, separated by spaces
        //  要添加的一个或多个标签，以空格分隔
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,
    },
    /// Remove one or more tags from a file or directory
    //  从一个文件或目录中删除一个或多个标签
    Remove {
        /// The path in the vault to remove tags from (e.g., "/docs/" or "/report.txt").
        /// Mutually exclusive with --hash.
        //  要从中删除标签的保险库内路径 (例如 "/docs/" 或 "/report.txt")。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to remove tags from.
        /// Mutually exclusive with --path.
        //  要从中删除标签的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// One or more tags to remove, separated by spaces
        //  要删除的一个或多个标签，以空格分隔
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,
    },
    /// Clear all tags from a file or directory
    //  清除一个文件或目录的所有标签
    Clear {
        /// The path in the vault to clear tags from (e.g., "/docs/" or "/report.txt").
        /// Mutually exclusive with --hash.
        //  要清除标签的保险库内路径 (例如 "/docs/" 或 "/report.txt")。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to clear tags from.
        /// Mutually exclusive with --path.
        //  要清除标签的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,
    },
    /// Set a display color for a file or directory (Requires 'colorfulTag' feature)
    //  设置文件或目录的显示颜色 (需要启用 'colorfulTag' 功能)
    Color {
        /// The path in the vault to color (e.g., "/docs/" or "/report.txt").
        /// Mutually exclusive with --hash.
        //  要设置颜色的保险库内路径。
        //  与 --hash 互斥。
        #[arg(short = 'p', long = "path", group = "source", required_unless_present = "hash")]
        path: Option<String>,

        /// The full 43-character hash of the file to color.
        /// Mutually exclusive with --path.
        //  要设置颜色的文件的完整 43 字符哈希。
        //  与 --path 互斥。
        #[arg(short = 'h', long = "hash", group = "source")]
        hash: Option<String>,

        /// The color to set. Allowed values: red, green, yellow, blue, magenta, cyan.
        /// Use "none" to remove the color.
        //  要设置的颜色。允许的值: red, green, yellow, blue, magenta, cyan。
        //  使用 "none" 移除颜色。
        #[arg(required = true)]
        color: String,
    },
}