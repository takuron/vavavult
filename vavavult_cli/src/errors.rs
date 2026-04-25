use std::io;
use std::path::PathBuf;
use thiserror::Error;
use vavavult::{
    file::path::PathError,
    vault::{
        AddFileError, CreateError, ExtractError, OpenError, QueryError, RekeyError, RemoveError,
        TagError, UpdateError,
    },
};

/// Defines errors that can occur within the CLI application.
//
// // 定义在 CLI 应用程序中可能发生的错误。
#[derive(Debug, Error)]
pub enum CliError {
    /// The specified vault path was not found.
    //
    // // 找不到指定的保险库路径。
    #[error("Vault not found at path: {0}")]
    VaultNotFound(PathBuf),

    /// An operation required an open vault, but none was open.
    //
    // // 操作需要打开的保险库，但没有打开任何保险库。
    #[error("Vault is not open. Please open or create a vault first.")]
    VaultNotOpen,

    /// An attempt was made to open a vault when one is already open.
    //
    // // 尝试打开保险库时，已有另一个保险库处于打开状态。
    #[error("A vault is already open at: {0}")]
    VaultAlreadyOpen(String),

    /// An invalid command was entered.
    //
    // // 输入了无效的命令。
    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    /// A target path provided for an operation was invalid.
    //
    // // 为操作提供的目标路径无效。
    #[error("Invalid target path: {0}")]
    InvalidTarget(String),

    /// The specified entry (file or directory) was not found in the vault.
    //
    // // 在保险库中找不到指定的条目（文件或目录）。
    #[error("The specified entry was not found in the vault: {0}")]
    EntryNotFound(String),

    /// A provided name was invalid.
    //
    // // 提供的名称无效。
    #[error("Invalid name provided: {0}")]
    InvalidName(String),

    /// A hash string was in an invalid format.
    //
    // // 哈希字符串的格式无效。
    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    /// The specified tag was not found.
    //
    // // 找不到指定的标签。
    #[error("The specified tag was not found: {0}")]
    TagNotFound(String),

    /// The user did not confirm an action.
    //
    // // 用户未确认操作。
    #[error("Action was not confirmed by the user.")]
    ConfirmationFailed,

    /// Passwords entered did not match.
    //
    // // 输入的密码不匹配。
    #[error("Passwords do not match.")]
    PasswordMismatch,

    /// An I/O error occurred.
    //
    // // 发生 I/O 错误。
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// An error occurred with the REPL readline functionality.
    //
    // // REPL 的 readline 功能发生错误。
    #[error("REPL Readline error: {0}")]
    Readline(#[from] rustyline::error::ReadlineError),

    /// A vault path error occurred.
    //
    // // 发生保险库路径错误。
    #[error("Invalid path: {0}")]
    Path(#[from] PathError),

    /// An error occurred while creating a vault.
    //
    // // 创建保险库时发生错误。
    #[error("Failed to create vault: {0}")]
    Create(#[from] CreateError),

    /// An error occurred while opening a vault.
    //
    // // 打开保险库时发生错误。
    #[error("Failed to open vault: {0}")]
    Open(#[from] OpenError),

    /// An error occurred while adding a file to the vault.
    //
    // // 向保险库添加文件时发生错误。
    #[error("Failed to add file to vault: {0}")]
    AddFile(#[from] AddFileError),

    /// An error occurred while extracting a file from the vault.
    //
    // // 从保险库提取文件时发生错误。
    #[error("Failed to extract file from vault: {0}")]
    Extract(#[from] ExtractError),

    /// An error occurred while querying the vault.
    //
    // // 查询保险库时发生错误。
    #[error("Failed to query vault: {0}")]
    Query(#[from] QueryError),

    /// An error occurred while removing from the vault.
    //
    // // 从保险库删除时发生错误。
    #[error("Failed to remove from vault: {0}")]
    Remove(#[from] RemoveError),

    /// An error occurred while re-keying the vault.
    //
    // // 对保险库进行密钥轮换时发生错误。
    #[error("Failed to rekey vault: {0}")]
    Rekey(#[from] RekeyError),

    /// An error occurred while processing a tag.
    //
    // // 处理标签时发生错误。
    #[error("Failed to process tag: {0}")]
    Tag(#[from] TagError),

    /// An error occurred while updating the vault.
    //
    // // 更新保险库时发生错误。
    #[error("Failed to update vault: {0}")]
    Update(#[from] UpdateError),

    /// An invalid command was entered in the REPL.
    //
    // // 在 REPL 中输入了无效的命令。
    #[error("Invalid command in REPL: {0}")]
    InvalidReplCommand(String),

    /// The home directory could not be found.
    //
    // // 找不到主目录。
    #[error("Could not find home directory")]
    NoHomeDir,

    /// The provided path is not a file.
    //
    // // 提供的路径不是文件。
    #[error("The provided path is not a file: {0}")]
    NotAFile(PathBuf),

    /// The provided path is not a directory.
    //
    // // 提供的路径不是目录。
    #[error("The provided path is not a directory: {0}")]
    NotADirectory(PathBuf),

    /// An unexpected error occurred.
    //
    // // 发生意外错误。
    #[error("An unexpected error occurred: {0}")]
    Unexpected(String),
}
