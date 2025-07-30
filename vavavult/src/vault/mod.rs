use std::path::{Path, PathBuf};
use rusqlite::Connection;

mod config;
mod create;
mod add;
mod common;
mod query;
mod update;
mod remove;

pub use config::{VaultConfig};
pub use create::{CreateError};
pub use add::{AddFileError};
pub use query::{QueryError, QueryResult};
pub use update::{UpdateError};
pub use remove::{RemoveError};

use crate::vault::add::add_file;
use crate::vault::create::create_vault;
use crate::vault::query::{check_by_hash, check_by_name};
use crate::vault::remove::remove_file;
use crate::vault::update::{add_tag, add_tags, clear_tags, remove_tag, rename_file};

/// Represents a vault loaded into memory.
/// It holds the vault's configuration and a live database connection.
pub struct Vault {
    /// The root path of the vault directory.
    pub root_path: PathBuf,
    /// The vault's configuration, loaded from `master.json`.
    pub config: VaultConfig,
    /// An open connection to the vault's database.
    pub database_connection: Connection,
}

impl Vault {
    /// Creates a new Vault at the specified path.
    ///
    /// This will create the root directory and initialize the `master.json`
    /// configuration and the `master.db` database.
    ///
    /// # Arguments
    /// * `root_path` - The path where the vault directory will be created.
    /// * `vault_name` - A name for the vault, stored in the configuration.
    ///
    /// # Errors
    /// Returns `CreateError` if the directory already exists and is not empty,
    /// or if there are I/O or database initialization errors.
    pub fn create_vault(root_path: &Path, vault_name: &str) -> Result<Vault, CreateError> {
        create_vault(root_path, vault_name)
    }

    /// Finds a file entry by its normalized path name.
    ///
    /// # Arguments
    /// * `name` - The normalized path name of the file (e.g., "/documents/report.txt").
    ///
    /// # Returns
    /// A `QueryResult` which is `Found(FileEntry)` if the file exists,
    /// or `NotFound` otherwise.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue or data inconsistency.
    pub fn find_by_name(&self, name: &str) -> Result<QueryResult, QueryError> {
        check_by_name(self, name)
    }

    /// Finds a file entry by its SHA256 hash.
    ///
    /// # Arguments
    /// * `sha256sum` - The SHA256 hash of the file content.
    ///
    /// # Returns
    /// A `QueryResult` which is `Found(FileEntry)` if the file exists,
    /// or `NotFound` otherwise.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue or data inconsistency.
    pub fn find_by_hash(&self, sha256sum: &str) -> Result<QueryResult, QueryError> {
        check_by_hash(self, sha256sum)
    }

    /// Adds a new file to the vault from a source path.
    ///
    /// The file's content is copied into the vault and a new database record is created.
    ///
    /// # Arguments
    /// * `source_path` - The path to the file on the local filesystem.
    /// * `dest_name` - An optional destination name/path for the file inside the vault.
    ///   If `None`, the original filename is used.
    ///
    /// # Returns
    /// The SHA256 hash of the added file on success.
    ///
    /// # Errors
    /// Returns `AddFileError` if the source file doesn't exist, or if a file with
    /// the same name or content already exists in the vault.
    pub fn add_file(
        &mut self,
        source_path: &Path,
        dest_name: Option<&str>,
    ) -> Result<String, AddFileError> {
        add_file(self, source_path, dest_name)
    }

    /// Renames a file identified by its SHA256 hash.
    ///
    /// This only changes the `name` property in the database. The physical file,
    /// named by its hash, is not affected.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to rename.
    /// * `new_name` - The new name for the file.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found or if the new name is already taken.
    pub fn rename_file(&self, sha256sum: &str, new_name: &str) -> Result<(), UpdateError> {
        rename_file(self, sha256sum, new_name)
    }

    /// Adds a single tag to a file.
    ///
    /// If the tag already exists on the file, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to tag.
    /// * `tag` - The tag to add.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn add_tag(&self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        add_tag(self, sha256sum, tag)
    }

    /// Adds multiple tags to a file in a single transaction.
    ///
    /// Existing tags are ignored.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to tag.
    /// * `tags` - A slice of string slices representing the tags to add.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn add_tags(&mut self, sha256sum: &str, tags: &[&str]) -> Result<(), UpdateError> {
        add_tags(self, sha256sum, tags)
    }

    /// Removes a single tag from a file.
    ///
    /// If the tag does not exist on the file, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file.
    /// * `tag` - The tag to remove.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn remove_tag(&self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        remove_tag(self, sha256sum, tag)
    }

    /// Removes all tags from a file.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to clear tags from.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn clear_tags(&self, sha256sum: &str) -> Result<(), UpdateError> {
        clear_tags(self, sha256sum)
    }

    /// Removes a file from the vault.
    ///
    /// This deletes both the database record (and all associated tags/metadata
    /// via cascading delete) and the physical file from the filesystem.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to remove.
    ///
    /// # Errors
    /// Returns `RemoveError` if the file is not found or if there is a filesystem error.
    pub fn remove_file(&self, sha256sum: &str) -> Result<(), RemoveError> {
        remove_file(self, sha256sum)
    }
}