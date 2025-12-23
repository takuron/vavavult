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

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Vault is not open. Please open or create a vault first.")]
    VaultNotOpen,

    #[error("A vault is already open at: {0}")]
    VaultAlreadyOpen(String),

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Invalid target path: {0}")]
    InvalidTarget(String),

    #[error("The specified entry was not found in the vault: {0}")]
    EntryNotFound(String),

    #[error("Invalid name provided: {0}")]
    InvalidName(String),

    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    #[error("The specified tag was not found: {0}")]
    TagNotFound(String),

    #[error("Action was not confirmed by the user.")]
    ConfirmationFailed,

    #[error("Passwords do not match.")]
    PasswordMismatch,

    #[error("I/O error")]
    Io(#[from] io::Error),

    #[error("REPL Readline error")]
    Readline(#[from] rustyline::error::ReadlineError),

    #[error("Invalid path")]
    Path(#[from] PathError),

    #[error("Failed to create vault")]
    Create(#[from] CreateError),

    #[error("Failed to open vault")]
    Open(#[from] OpenError),

    #[error("Failed to add file to vault")]
    AddFile(#[from] AddFileError),

    #[error("Failed to extract file from vault")]
    Extract(#[from] ExtractError),

    #[error("Failed to query vault")]
    Query(#[from] QueryError),

    #[error("Failed to remove from vault")]
    Remove(#[from] RemoveError),

    #[error("Failed to rekey vault")]
    Rekey(#[from] RekeyError),

    #[error("Failed to process tag")]
    Tag(#[from] TagError),

    #[error("Failed to update vault")]
    Update(#[from] UpdateError),

    #[error("Invalid command in REPL: {0}")]
    InvalidReplCommand(String),

    #[error("Could not find home directory")]
    NoHomeDir,

    #[error("The provided path is not a file: {0}")]
    NotAFile(PathBuf),

    #[error("The provided path is not a directory: {0}")]
    NotADirectory(PathBuf),

    #[error("An unexpected error occurred: {0}")]
    Unexpected(String),
}
