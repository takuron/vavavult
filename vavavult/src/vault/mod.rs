use std::path::{Path, PathBuf};
use rusqlite::Connection;

mod config;
mod create;
mod add;
mod query;
mod update;
mod remove;
mod extract;

pub use config::{VaultConfig};
pub use create::{CreateError,OpenError};
pub use add::{AddFileError};
pub use query::{QueryError, QueryResult};
pub use update::{UpdateError};
pub use remove::{RemoveError};
pub use query::{ListResult};
use crate::common::metadata::MetadataEntry;
pub use crate::file::FileEntry;
use crate::vault::add::add_file;
use crate::vault::create::{create_vault, open_vault};
use crate::vault::extract::{extract_file, ExtractError};
use crate::vault::query::{check_by_hash, check_by_name, find_by_name_and_tag_fuzzy, find_by_name_fuzzy, find_by_tag, list_all_files, list_by_path};
use crate::vault::remove::remove_file;
use crate::vault::update::{add_tag, add_tags, clear_tags, remove_file_metadata, remove_tag, remove_vault_metadata, rename_file, set_file_metadata, set_name, set_vault_metadata,touch_vault_update_time};

/// Represents a vault loaded into memory.
///
/// It holds the vault's configuration and a live database connection,
/// providing the primary interface for all vault operations.
#[derive(Debug)]
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
    /// * `password` - An optional password. If provided, the vault will be encrypted.
    ///
    /// # Errors
    /// Returns `CreateError` if the directory already exists and is not empty,
    /// or if there are I/O or database initialization errors.
    pub fn create_vault(root_path: &Path, vault_name: &str, password: Option<&str>) -> Result<Vault, CreateError> {
        create_vault(root_path, vault_name, password)
    }

    /// Opens an existing Vault from the specified path.
    ///
    /// # Arguments
    /// * `root_path` - The path to the existing vault directory.
    /// * `password` - An optional password. Required if the vault is encrypted.
    ///
    /// # Errors
    /// Returns `OpenError` if the path does not exist, the configuration
    /// is missing or corrupt, or if an incorrect password is provided for an
    /// encrypted vault.
    pub fn open_vault(root_path: &Path, password: Option<&str>) -> Result<Vault, OpenError> {
        // [修改] 将 password 参数传递给后端的 open_vault 函数
        open_vault(root_path, password)
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

    /// Lists all files currently stored in the vault.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn list_all(&self) -> Result<Vec<FileEntry>, QueryError> {
        list_all_files(self)
    }

    /// Lists files and subdirectories directly under a given path.
    ///
    /// For example, querying for `/` might return files like `/a.txt` and `/b.txt`,
    /// and subdirectories like `c`.
    ///
    /// # Arguments
    /// * `path` - The path to list (e.g., "/", "/documents/").
    ///
    /// # Returns
    /// A `ListResult` containing separate vectors for files and subdirectory names.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn list_by_path(&self, path: &str) -> Result<ListResult, QueryError> {
        list_by_path(self, path)
    }

    /// Finds all files associated with a specific tag.
    ///
    /// # Arguments
    /// * `tag` - The tag to search for.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn find_by_tag(&self, tag: &str) -> Result<Vec<FileEntry>, QueryError> {
        find_by_tag(self, tag)
    }

    /// Finds all files whose name contains a given pattern (case-insensitive).
    ///
    /// # Arguments
    /// * `name_pattern` - The substring to search for within file names.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn find_by_name_fuzzy(
        &self,
        name_pattern: &str,
    ) -> Result<Vec<FileEntry>, QueryError> {
        find_by_name_fuzzy(self, name_pattern)
    }

    /// Finds all files that have a specific tag and whose name contains a given pattern.
    ///
    /// # Arguments
    /// * `name_pattern` - The substring to search for within file names.
    /// * `tag` - The tag that files must be associated with.
    ///
    /// # Returns
    /// A `Vec<FileEntry>` containing all matching files.
    ///
    /// # Errors
    /// Returns `QueryError` if there is a database issue.
    pub fn find_by_name_and_tag_fuzzy(
        &self,
        name_pattern: &str,
        tag: &str,
    ) -> Result<Vec<FileEntry>, QueryError> {
        find_by_name_and_tag_fuzzy(self, name_pattern, tag)
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
        let result = add_file(self, source_path, dest_name)?;
        touch_vault_update_time(self)?;
        Ok(result)
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
    pub fn rename_file(&mut self, sha256sum: &str, new_name: &str) -> Result<(), UpdateError> {
        rename_file(self, sha256sum, new_name)?;
        touch_vault_update_time(self)
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
    pub fn add_tag(&mut self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        add_tag(self, sha256sum, tag)?;
        touch_vault_update_time(self)
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
        add_tags(self, sha256sum, tags)?;
        touch_vault_update_time(self)
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
    pub fn remove_tag(&mut self, sha256sum: &str, tag: &str) -> Result<(), UpdateError> {
        remove_tag(self, sha256sum, tag)?;
        touch_vault_update_time(self)
    }

    /// Removes all tags from a file.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to clear tags from.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn clear_tags(&mut self, sha256sum: &str) -> Result<(), UpdateError> {
        clear_tags(self, sha256sum)?;
        touch_vault_update_time(self)
    }

    /// Sets a metadata key-value pair for a file.
    ///
    /// If the key already exists, its value will be updated. If it does not exist,
    /// a new key-value pair will be created.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to modify.
    /// * `key` - The metadata key.
    /// * `value` - The metadata value.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn set_file_metadata(&mut self, sha256sum: &str, metadata:MetadataEntry) -> Result<(), UpdateError> {
        set_file_metadata(self, sha256sum, metadata)?;
        touch_vault_update_time(self)
    }

    /// Removes a metadata key-value pair from a file.
    ///
    /// If the key does not exist, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to modify.
    /// * `key` - The metadata key to remove.
    ///
    /// # Errors
    /// Returns `UpdateError` if the file is not found.
    pub fn remove_file_metadata(&mut self, sha256sum: &str, key: &str) -> Result<(), UpdateError> {
        remove_file_metadata(self, sha256sum, key)?;
        touch_vault_update_time(self)
    }

    /// Extracts a file from the vault to a specified destination path.
    ///
    /// This copies the physical file from the vault's internal storage to a
    /// location on the external filesystem.
    ///
    /// # Arguments
    /// * `sha256sum` - The hash of the file to extract.
    /// * `destination_path` - The full path (including filename) where the file will be saved.
    ///
    /// # Errors
    /// Returns `ExtractError` if the file is not found in the vault or if there
    /// is a filesystem error during the copy.
    pub fn extract_file(&self, sha256sum: &str, destination_path: &Path) -> Result<(), ExtractError> {
        extract_file(self, sha256sum, destination_path)
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
    pub fn remove_file(&mut self, sha256sum: &str) -> Result<(), RemoveError> {
        remove_file(self, sha256sum)?;
        touch_vault_update_time(self)?;
        Ok(())
    }

    /// Sets the name of the vault.
    ///
    /// This updates the `name` property in the in-memory config and writes the
    /// change to the `master.json` file.
    ///
    /// # Arguments
    /// * `new_name` - The new name for the vault.
    ///
    /// # Errors
    /// Returns `UpdateError` if the configuration cannot be serialized or written to disk.
    pub fn set_name(&mut self, new_name: &str) -> Result<(), UpdateError> {
        set_name(self, new_name)?;
        touch_vault_update_time(self)
    }
    /// Sets a metadata key-value pair for the vault itself.
    ///
    /// This is an "upsert" operation. If the key already exists, its value is
    /// updated. If not, a new entry is created.
    ///
    /// # Arguments
    /// * `metadata` - The `MetadataEntry` to set in the vault's configuration.
    ///
    /// # Errors
    /// Returns `UpdateError` on I/O or serialization issues.
    pub fn set_vault_metadata(&mut self, metadata: MetadataEntry) -> Result<(), UpdateError> {
        set_vault_metadata(self, metadata)?;
        touch_vault_update_time(self)
    }

    /// Removes a metadata key-value pair from the vault.
    ///
    /// If the key does not exist, the operation succeeds with no change.
    ///
    /// # Arguments
    /// * `key` - The key of the metadata entry to remove.
    ///
    /// # Errors
    /// Returns `UpdateError` on I/O or serialization issues if the key is removed.
    pub fn remove_vault_metadata(&mut self, key: &str) -> Result<(), UpdateError> {
        remove_vault_metadata(self, key)?;
        touch_vault_update_time(self)
    }
}