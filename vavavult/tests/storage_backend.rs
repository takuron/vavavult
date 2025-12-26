use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use vavavult::common::constants::DATA_SUBDIR;
use vavavult::common::hash::VaultHash;
use vavavult::file::VaultPath;
use vavavult::storage::{StagingToken, StorageBackend};
use vavavult::vault::{QueryResult, Vault};

// --- Mock In-Memory Storage (内存存储模拟) ---
// 这个模拟后端将文件数据存储在 HashMap 中，而不是磁盘上。
// 用来验证业务逻辑不依赖于物理文件系统。

#[derive(Debug, Clone)]
struct InMemoryStorage {
    files: Arc<Mutex<HashMap<VaultHash, Vec<u8>>>>,
}

impl InMemoryStorage {
    fn new() -> Self {
        Self { files: Arc::new(Mutex::new(HashMap::new())) }
    }
}

#[derive(Debug)]
struct MemoryStagingToken {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl StagingToken for MemoryStagingToken {
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

struct MemoryWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut data = self.buffer.lock().unwrap();
        data.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl StorageBackend for InMemoryStorage {
    fn exists(&self, hash: &VaultHash) -> io::Result<bool> {
        Ok(self.files.lock().unwrap().contains_key(hash))
    }

    fn reader(&self, hash: &VaultHash) -> io::Result<Box<dyn io::Read + Send>> {
        let map = self.files.lock().unwrap();
        let data = map.get(hash).ok_or(io::Error::new(io::ErrorKind::NotFound, "File not found in memory"))?;
        Ok(Box::new(Cursor::new(data.clone())))
    }

    fn prepare_write(&self) -> io::Result<(Box<dyn Write + Send>, Box<dyn StagingToken>)> {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        // 返回 Writer 用于写入数据，返回 Token 用于后续提交
        Ok((Box::new(MemoryWriter { buffer: buffer.clone() }), Box::new(MemoryStagingToken { buffer })))
    }

    fn commit_write(&self, mut token: Box<dyn StagingToken>, final_hash: &VaultHash) -> io::Result<()> {
        // 从 Token 中取出暂存数据，移动到主存储 (HashMap)
        let mem_token = token.as_any_mut().downcast_mut::<MemoryStagingToken>().unwrap();
        let data = mem_token.buffer.lock().unwrap().clone();
        self.files.lock().unwrap().insert(final_hash.clone(), data);
        Ok(())
    }

    fn rollback_write(&self, _token: Box<dyn StagingToken>) -> io::Result<()> { Ok(()) }

    fn delete(&self, hash: &VaultHash) -> io::Result<()> {
        self.files.lock().unwrap().remove(hash);
        Ok(())
    }
}

/// 测试：验证存储解耦。
/// 验证当注入 InMemoryStorage 时：
/// 1. 物理磁盘的 `data/` 目录不应包含任何数据文件。
/// 2. 数据应该存在于内存后端中。
/// 3. 提取操作应该能从内存后端正确读取数据。
#[test]
fn test_decoupling_with_in_memory_backend() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("mem-vault");
    let memory_backend = Arc::new(InMemoryStorage::new());

    // 注入自定义后端
    let mut vault = Vault::create_vault(&vault_path, "mem-test", Some("pass"), memory_backend.clone()).unwrap();

    let source_path = dir.path().join("source.txt");
    fs::write(&source_path, "RAM Data").unwrap();
    let hash = vault.add_file(&source_path, &VaultPath::from("/file.txt")).unwrap();

    // 验证物理隔离：磁盘上的 data 目录不应有文件
    assert!(!vault.root_path.join(DATA_SUBDIR).join(hash.to_string()).exists());
    // 验证内存存储：后端应有数据
    assert!(memory_backend.exists(&hash).unwrap());

    // 验证提取
    let extract_path = dir.path().join("out.txt");
    vault.extract_file(&hash, &extract_path).unwrap();
    assert_eq!(fs::read_to_string(extract_path).unwrap(), "RAM Data");
}

/// 测试：模拟存储持久性。
/// 验证如果后端能在 Vault 关闭后存活（例如 S3 或持久化的内存模拟），
/// 重新打开 Vault 并注入相同的后端，依然能访问数据。
#[test]
fn test_memory_backend_persistence_simulation() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("mem-vault-2");
    let memory_backend = Arc::new(InMemoryStorage::new());
    let source_path = dir.path().join("source.txt");
    fs::write(&source_path, "Persist?").unwrap();

    // 步骤 1: 创建并添加
    {
        let mut vault = Vault::create_vault(&vault_path, "test", Some("pass"), memory_backend.clone()).unwrap();
        vault.add_file(&source_path, &VaultPath::from("/f.txt")).unwrap();
    } // vault 在此处被 Drop (模拟关闭)

    // 步骤 2: 重新打开，注入同一个后端实例
    let reopened = Vault::open_vault(&vault_path, Some("pass"), memory_backend.clone()).unwrap();

    // 验证元数据存在（来自 SQLite）
    let entry = match reopened.find_by_path(&VaultPath::from("/f.txt")).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("Metadata lost"),
    };

    // 验证内容存在（来自 MemoryBackend）
    let extract_path = dir.path().join("out.txt");
    reopened.extract_file(&entry.sha256sum, &extract_path).unwrap();
    assert_eq!(fs::read_to_string(extract_path).unwrap(), "Persist?");
}