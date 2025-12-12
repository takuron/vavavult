use rayon::prelude::*;
use sha2::{Digest, Sha512};
use std::fs;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use vavavult::common::constants::DATA_SUBDIR;
use vavavult::file::VaultPath;
use vavavult::vault::{AddFileError, ExtractionTask, QueryResult};
use vavavult::vault::{execute_extraction_task_standalone, prepare_addition_task_standalone};

mod common;
use common::{
    create_dummy_file, create_dummy_files, setup_encrypted_vault, setup_vault_with_search_data,
};

/// 测试：完整的文件生命周期 (添加 -> 查询 -> 提取)。
/// 验证数据的完整性：写入的内容 = 读取的内容。
#[test]
fn test_add_file_and_extract_file_cycle() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let dummy_file_path = create_dummy_file(&dir, "hello.txt", "Hello V2 Integrity");

    // 1. 添加文件
    let dest_path = VaultPath::from("/docs/hello.txt");
    let encrypted_hash = vault.add_file(&dummy_file_path, &dest_path).unwrap();

    // 2. 验证文件已存在于数据库，且路径正确
    let entry = match vault.find_by_path(&dest_path).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File not found"),
    };
    assert_eq!(entry.sha256sum, encrypted_hash);

    // 3. 提取文件并对比内容
    let extract_path = dir.path().join("extracted.txt");
    vault.extract_file(&encrypted_hash, &extract_path).unwrap();
    assert_eq!(
        fs::read_to_string(&extract_path).unwrap(),
        "Hello V2 Integrity"
    );
}

/// 测试：添加文件时的各种错误情况。
/// 验证：
/// 1. 相同路径不能添加两次 (DuplicateFileName)。
/// 2. 相同内容不能添加两次 (去重机制, DuplicateOriginalContent)。
#[test]
fn test_add_file_paths_and_errors() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file1_path = create_dummy_file(&dir, "file1.txt", "content1");
    let file2_path = create_dummy_file(&dir, "file2.txt", "content2");

    let path1 = VaultPath::from("/file1.txt");
    vault.add_file(&file1_path, &path1).unwrap();

    // 错误 1: 尝试向已存在的路径添加不同文件
    assert!(matches!(
        vault.add_file(&file2_path, &path1).unwrap_err(),
        AddFileError::DuplicateFileName(_)
    ));

    // 错误 2: 尝试添加内容完全相同的文件 (即使路径不同)
    let path2 = VaultPath::from("/file1_copy.txt");
    assert!(matches!(
        vault.add_file(&file1_path, &path2).unwrap_err(),
        AddFileError::DuplicateOriginalContent(_, _)
    ));
}

/// 测试：文件的移动和重命名。
/// 验证 `move_file` 和 `rename_file_inplace` 能正确更新数据库路径。
#[test]
fn test_move_and_rename_file() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "move.txt", "content");
    let hash = vault
        .add_file(&file_path, &VaultPath::from("/dir1/move.txt"))
        .unwrap();

    // 测试重命名 (保持父目录不变)
    vault.rename_file_inplace(&hash, "renamed.txt").unwrap();
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/dir1/renamed.txt"))
            .unwrap(),
        QueryResult::Found(_)
    ));

    // 测试移动 (改变目录)
    vault.move_file(&hash, &VaultPath::from("/dir2/")).unwrap();
    assert!(matches!(
        vault
            .find_by_path(&VaultPath::from("/dir2/renamed.txt"))
            .unwrap(),
        QueryResult::Found(_)
    ));
}

/// 测试：文件删除。
/// 验证删除后：
/// 1. 物理文件从 `data/` 目录移除。
/// 2. 数据库记录消失。
#[test]
fn test_remove_file() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);
    let file_path = create_dummy_file(&dir, "del.txt", "content");
    let hash = vault
        .add_file(&file_path, &VaultPath::from("/del.txt"))
        .unwrap();

    let internal_path = vault.root_path.join(DATA_SUBDIR).join(hash.to_string());
    assert!(internal_path.exists());

    vault.remove_file(&hash).unwrap();

    assert!(!internal_path.exists());
    assert!(matches!(
        vault.find_by_hash(&hash).unwrap(),
        QueryResult::NotFound
    ));
}

/// 测试：大文件完整性。
/// 验证流式加密/解密逻辑在处理超出缓冲区大小的文件时是否正确。
/// 这是一个关键的测试，用于验证 `stream_cipher` 的逻辑。
#[test]
fn test_large_file_integrity() {
    let dir = tempdir().unwrap();
    let (_vault_path, mut vault) = setup_encrypted_vault(&dir);

    // 16MB 测试，减少测试时间但足够验证流处理 (buffer 通常 8KB)
    const FILE_SIZE: usize = 16 * 1024 * 1024;
    let mut buffer = vec![0u8; 8192];
    let source_path = dir.path().join("large.bin");
    let mut source_file = fs::File::create(&source_path).unwrap();
    let mut hasher = Sha512::new();

    // 生成随机内容并计算原始 SHA512
    let mut written = 0;
    while written < FILE_SIZE {
        let chunk_size = std::cmp::min(8192, FILE_SIZE - written);
        openssl::rand::rand_bytes(&mut buffer[..chunk_size]).unwrap();
        source_file.write_all(&buffer[..chunk_size]).unwrap();
        hasher.update(&buffer[..chunk_size]);
        written += chunk_size;
    }
    let original_hash = hex::encode(hasher.finalize());

    // 添加到 Vault 并重新提取
    let hash = vault
        .add_file(&source_path, &VaultPath::from("/large.bin"))
        .unwrap();
    let extract_path = dir.path().join("extracted.bin");
    vault.extract_file(&hash, &extract_path).unwrap();

    // 计算提取文件的 SHA512
    let mut ext_hasher = Sha512::new();
    let mut ext_file = fs::File::open(&extract_path).unwrap();
    loop {
        let n = ext_file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        ext_hasher.update(&buffer[..n]);
    }
    // 核心断言：SHA512 必须完全匹配
    assert_eq!(original_hash, hex::encode(ext_hasher.finalize()));
}

/// 测试：搜索和列表功能。
/// 验证 `find_by_hashes`, `find_by_keyword`, `list_all`, `list_entries_by_path` API。
#[test]
fn test_batch_queries_and_search() {
    let dir = tempdir().unwrap();
    let (vault, hash_a, _, hash_c, _) = setup_vault_with_search_data(&dir);

    // 1. 批量哈希查询
    let res = vault
        .find_by_hashes(&[hash_a.clone(), hash_c.clone()])
        .unwrap();
    assert_eq!(res.len(), 2);

    // 2. 关键字搜索 (包含路径和标签)
    let res_kw = vault.find_by_keyword("docs").unwrap();
    assert_eq!(res_kw.len(), 2); // file_B, file_C

    // 3. 列出所有
    assert_eq!(vault.list_all().unwrap().len(), 4);

    // 4. 目录层级列表
    let entries = vault.list_by_path(&VaultPath::from("/docs/")).unwrap();
    assert_eq!(entries.len(), 2); // deep/, file_B.md
}

/// 测试：并行 API。
/// 模拟 CLI 的行为，使用 `encrypt_file_for_add_standalone` 和 `execute_extraction_task_standalone`
/// 来在多个线程中并行处理加密和解密，不持有 Vault 锁。
#[test]
fn test_parallel_add_and_extract() {
    let dir = tempdir().unwrap();
    let (_vault_path, vault) = setup_encrypted_vault(&dir);
    // 使用 Arc<Mutex> 模拟 CLI 中的共享状态
    let vault_arc = Arc::new(Mutex::new(vault));

    let file_count = 10;
    let source_files = create_dummy_files(&dir, file_count, "parallel");

    // --- 阶段 1: 并行添加 ---
    // 获取 storage 引用，无需锁住 Vault
    let storage = vault_arc.lock().unwrap().storage.clone();

    // 使用 Rayon 并行加密
    let encrypted_files: Vec<_> = source_files
        .par_iter()
        .enumerate()
        .map(|(i, (src, _))| {
            let dest = VaultPath::from(format!("/p_file_{}.txt", i).as_str());
            prepare_addition_task_standalone(storage.as_ref(), src, &dest).unwrap()
        })
        .collect();

    // 快速的批量提交 (持有锁时间很短)
    {
        let mut v = vault_arc.lock().unwrap();
        v.execute_addition_tasks(encrypted_files).unwrap();
    }

    // --- 阶段 2: 并行提取 ---
    let all_files = vault_arc.lock().unwrap().list_all().unwrap();
    let extract_dir = dir.path().join("ext");
    fs::create_dir_all(&extract_dir).unwrap();

    // 准备任务 (快速锁)
    let tasks: Vec<(ExtractionTask, std::path::PathBuf)> = {
        let v = vault_arc.lock().unwrap();
        all_files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                (
                    v.prepare_extraction_task(&f.sha256sum).unwrap(),
                    extract_dir.join(format!("out_{}.txt", i)),
                )
            })
            .collect()
    };

    // 执行任务 (无锁并行)
    let storage_ext = vault_arc.lock().unwrap().storage.clone();
    tasks.par_iter().for_each(|(task, path)| {
        execute_extraction_task_standalone(storage_ext.as_ref(), task, path).unwrap();
    });

    assert_eq!(fs::read_dir(extract_dir).unwrap().count(), file_count);
}

/// Tests the file integrity verification feature.
/// Verifies that a known-good file passes the check, and a corrupted file fails.
#[test]
fn test_file_integrity_check() {
    let dir = tempdir().unwrap();
    let (vault_path, mut vault) = setup_encrypted_vault(&dir);
    let dummy_file_path = create_dummy_file(&dir, "integrity.txt", "This file is integral.");

    // 1. Add file
    let dest_path = VaultPath::from("/docs/integrity.txt");
    let encrypted_hash = vault.add_file(&dummy_file_path, &dest_path).unwrap();

    // 2. Verify integrity of the good file and assert it's OK
    assert!(vault.verify_file_integrity(&dest_path).is_ok());

    // 3. Corrupt the file in storage
    let stored_file_path = vault_path
        .join(DATA_SUBDIR)
        .join(encrypted_hash.to_string());
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(stored_file_path)
        .unwrap();
    file.write_all(b"CORRUPTION").unwrap();

    // 4. Verify integrity of the corrupted file and assert it's an error
    let verification_result = vault.verify_file_integrity(&dest_path);
    assert!(verification_result.is_err());
}
