#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;

/// 辅助函数：创建一个带默认密码的 V2 加密保险库。
///
/// 这个函数封装了创建 TempDir、构建路径和调用 `Vault::create_vault_local` 的样板代码。
/// 它返回 `(PathBuf, Vault)` 元组，让测试既能访问文件系统路径，又能获得 Vault 实例。
pub fn setup_encrypted_vault(dir: &TempDir) -> (PathBuf, Vault) {
    let vault_path = dir.path().join("test-vault");
    // 使用 "v2-password" 作为默认密码创建加密库
    let vault = Vault::create_vault_local(&vault_path, "test-vault", Some("v2-password")).unwrap();
    (vault_path, vault)
}

/// 辅助函数：创建一个具有指定密码的 V2 加密保险库。
pub fn setup_encrypted_vault_with_password(dir: &TempDir, password: &str) -> (PathBuf, Vault) {
    let vault_path = dir.path().join("test-vault");
    let vault = Vault::create_vault_local(&vault_path, "test-vault", Some(password)).unwrap();
    (vault_path, vault)
}

/// 辅助函数：在临时目录中创建一个具有特定内容的虚拟文件。
///
/// 这用于模拟用户本地文件系统上的源文件。
pub fn create_dummy_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let file_path = dir.path().join(name);
    let mut file = fs::File::create(&file_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file_path
}

/// 辅助函数：在临时目录中批量创建多个虚拟文件。
///
/// 用于并行处理或批量添加的测试场景。
/// 返回 `(文件路径, 文件内容)` 的列表，方便后续验证内容完整性。
pub fn create_dummy_files(dir: &TempDir, count: usize, prefix: &str) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    for i in 0..count {
        let file_name = format!("{}_{:03}.txt", prefix, i);
        let content = format!("content for file {} {}!", prefix, i);
        let file_path = dir.path().join(&file_name);
        fs::write(&file_path, &content).unwrap();
        files.push((file_path, content));
    }
    files
}

/// 辅助函数：创建一个包含预置数据的保险库，用于搜索和列表功能的测试。
///
/// 预置数据结构如下：
/// - /file_A.txt (tags: tag1, common) -> hash_a
/// - /docs/file_B.md (tags: tag2, common) -> hash_b
/// - /docs/deep/file_C.jpg (tags: tag3, image) -> hash_c
/// - /another_file.txt (tags: tag1, unique) -> hash_d
///
/// 返回 Vault 实例以及这四个文件的哈希值，方便测试断言。
pub fn setup_vault_with_search_data(
    dir: &TempDir,
) -> (
    Vault,
    vavavult::common::hash::VaultHash,
    vavavult::common::hash::VaultHash,
    vavavult::common::hash::VaultHash,
    vavavult::common::hash::VaultHash,
) {
    let (_vault_path, mut vault) = setup_encrypted_vault(dir);

    // 1. 创建源文件
    let file_a_path = create_dummy_file(dir, "file_A.txt", "content A");
    let file_b_path = create_dummy_file(dir, "file_B.md", "content B");
    let file_c_path = create_dummy_file(dir, "file_C.jpg", "content C");
    let file_d_path = create_dummy_file(dir, "another_file.txt", "content D");

    // 2. 添加文件到保险库
    let hash_a = vault
        .add_file(&file_a_path, &VaultPath::from("/file_A.txt"))
        .unwrap();
    let hash_b = vault
        .add_file(&file_b_path, &VaultPath::from("/docs/file_B.md"))
        .unwrap();
    let hash_c = vault
        .add_file(&file_c_path, &VaultPath::from("/docs/deep/file_C.jpg"))
        .unwrap();
    let hash_d = vault
        .add_file(&file_d_path, &VaultPath::from("/another_file.txt"))
        .unwrap();

    // 3. 为文件打标签，构建丰富的搜索场景
    vault.add_tag(&hash_a, "tag1").unwrap();
    vault.add_tag(&hash_a, "common").unwrap();
    vault.add_tag(&hash_b, "tag2").unwrap();
    vault.add_tag(&hash_b, "common").unwrap();
    vault.add_tag(&hash_c, "tag3").unwrap();
    vault.add_tag(&hash_c, "image").unwrap();
    vault.add_tag(&hash_d, "tag1").unwrap();
    vault.add_tag(&hash_d, "unique").unwrap();

    (vault, hash_a, hash_b, hash_c, hash_d)
}
