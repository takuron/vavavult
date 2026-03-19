# Vavavult Mount — WebDAV 扩展架构文档

> **目标读者**：负责实现 `vavavult_mount` crate 的开发者或 LLM。
> **前置知识**：请先阅读项目根目录下的 `llm_readme.txt`，了解整体项目结构和编码规范。
> **对应计划**：本文档是 `docs/TODO.md` 中 "Vavavult Mount" 开发计划的详细架构补充。

---

## 1. 概述

`vavavult_mount` 是 `vavavult` workspace 中的一个独立 library crate，其职责是将一个已打开的 `Vault` 实例通过 WebDAV 协议暴露为虚拟文件系统，支持：

- **挂载 (Mount)**：操作系统或 WebDAV 客户端可直接挂载并浏览/读取 Vault 中的文件。
- **简单分享 (Share)**：通过 HTTP 在局域网内提供文件库的只读或读写访问。

---

## 2. 目录结构

```text
vavavult_mount/
├── Cargo.toml
├── src/
│   ├── lib.rs              # crate 入口，模块注册与公共 API 导出
│   ├── error.rs            # 统一错误类型 MountError
│   ├── config.rs           # MountConfig, AuthConfig 配置结构体
│   ├── server.rs           # WebDAV 服务器启动/停止/生命周期管理
│   ├── auth.rs             # HTTP Basic Auth 中间件
│   └── vfs/                # 虚拟文件系统层 (核心)
│       ├── mod.rs           # VaultDavFs 结构体 + DavFileSystem trait 实现
│       ├── node.rs          # VaultDavFile 结构体 + DavFile trait 实现
│       └── metadata.rs      # FileEntry 元数据 → WebDAV 属性的映射辅助函数
└── tests/
    ├── common/
    │   └── mod.rs           # 测试辅助工具
    ├── vfs_test.rs          # VFS 层单元测试
    └── server_test.rs       # 集成测试 (HTTP 客户端 → WebDAV 服务器)
```

---

## 3. 依赖关系

### 3.1 Crate 间依赖

```text
vavavult_cli
    ├── vavavult          (核心库)
    └── vavavult_mount    (本 crate)
            └── vavavult  (核心库)
```

`vavavult_mount` 依赖 `vavavult` 核心库，通过其公共 API 操作 Vault。`vavavult_cli` 依赖 `vavavult_mount` 来提供 `mount`/`unmount` REPL 命令。

### 3.2 外部依赖

需要在 workspace `Cargo.toml` 的 `[workspace.dependencies]` 中添加以下依赖，供 `vavavult_mount` 使用：

| 依赖 | 版本建议 | 用途 |
|---|---|---|
| `dav-server` | `0.7` | WebDAV 协议处理框架，提供 `DavFileSystem` / `DavFile` trait |
| `tokio` | `1`, features: `["full"]` | 异步运行时 |
| `hyper` | `1`, features: `["server", "http1"]` | HTTP 服务器 |
| `http-body-util` | `0.1` | HTTP body 工具（hyper 1.x 配套） |
| `hyper-util` | `0.1`, features: `["tokio"]` | hyper + tokio 集成工具 |
| `bytes` | `1` | 高效字节缓冲区（`dav-server` 通常需要） |
| `futures` | `0.3` | 异步 Stream 辅助 |
| `log` | `0.4` | 日志门面 |

`vavavult_mount/Cargo.toml` 示例：

```toml
[package]
name = "vavavult_mount"
version = "0.1.0"
edition = "2024"

[dependencies]
vavavult = { path = "../vavavult" }
dav-server = { workspace = true }
tokio = { workspace = true }
hyper = { workspace = true }
http-body-util = { workspace = true }
hyper-util = { workspace = true }
bytes = { workspace = true }
futures = { workspace = true }
log = { workspace = true }
thiserror = { workspace = true }
base64 = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
reqwest = { version = "0.12", features = ["blocking"] }
```

---

## 4. 核心模块详细设计

### 4.1 `error.rs` — 统一错误类型

```rust
/// vavavult_mount 统一错误类型。
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// Vault 操作相关错误 (查询、提取、添加等)。
    #[error("Vault operation error: {0}")]
    VaultError(String),

    /// IO 错误 (网络绑定、文件操作等)。
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP/WebDAV 服务器错误。
    #[error("Server error: {0}")]
    ServerError(String),

    /// 认证相关错误。
    #[error("Authentication error: {0}")]
    AuthError(String),

    /// 配置无效。
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
```

### 4.2 `config.rs` — 配置结构体

```rust
/// WebDAV 挂载服务的配置。
pub struct MountConfig {
    /// 监听地址，默认 "127.0.0.1"（仅本机访问）。
    /// 设为 "0.0.0.0" 可允许局域网访问。
    pub bind_address: String,

    /// 监听端口，默认 8080。
    pub port: u16,

    /// 是否为只读模式。默认 true，安全优先。
    /// 为 true 时，PUT / DELETE / MOVE 等写入操作返回 403。
    pub read_only: bool,

    /// 可选的 HTTP Basic Auth 配置。
    /// 为 None 时不需要认证（仅建议本机使用）。
    pub auth: Option<AuthConfig>,

    /// WebDAV URL 路径前缀，默认 "/"。
    pub prefix: String,
}

/// HTTP Basic Auth 凭据。
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            read_only: true,
            auth: None,
            prefix: "/".to_string(),
        }
    }
}
```

---

### 4.3 `vfs/mod.rs` — VaultDavFs (核心)

这是整个扩展的**核心模块**，负责将 Vault 的目录结构映射为 `dav-server` 的虚拟文件系统。

#### 4.3.1 结构体定义

```rust
use std::sync::{Arc, Mutex};
use vavavult::vault::Vault;

/// 将 Vault 暴露为 WebDAV 虚拟文件系统的适配器。
///
/// 通过 Arc<Mutex<Vault>> 持有 Vault 的共享引用，
/// 与 CLI 的 AppState 使用相同的共享模式。
pub struct VaultDavFs {
    /// 对已打开 Vault 的共享引用。
    vault: Arc<Mutex<Vault>>,

    /// 是否为只读模式。
    read_only: bool,
}
```

#### 4.3.2 DavFileSystem trait 实现要点

`dav-server::DavFileSystem` trait 要求实现以下核心方法（签名可能因版本略有不同，以实际 crate 文档为准）：

| trait 方法 | 实现策略 |
|---|---|
| `metadata(path)` | 锁定 Vault → 将 WebDAV 路径转为 `VaultPath` → 调用 `vault.find_by_path()` → 将 `FileEntry` 转为 `DavMetaData` |
| `read_dir(path, meta)` | 锁定 Vault → 调用 `vault.list_by_path()` → 将 `Vec<DirectoryEntry>` 转为 `DavDirEntry` 流 |
| `open(path, options)` | **两阶段操作**：锁定 Vault → `prepare_extraction_task()` (阶段1) → 释放锁 → `spawn_blocking` 中执行 `execute_extraction_task_standalone()` (阶段2) → 返回 `VaultDavFile` |
| `create_dir(path)` | 只读模式返回 403；读写模式可直接返回 Ok（Vault 目录是隐式的） |
| `remove_file(path)` | 只读模式返回 403；读写模式锁定 Vault → `find_by_path()` → `remove_file()` |
| `rename(from, to)` | 只读模式返回 403；读写模式锁定 Vault → `find_by_path()` → `move_file()` |

#### 4.3.3 路径转换

WebDAV 客户端发来的路径是 URL 路径（如 `/docs/report.txt`），需要转换为 `VaultPath`：

```rust
/// 将 WebDAV 请求路径转为 VaultPath。
///
/// dav-server 传入的路径已经是绝对路径（以 "/" 开头），
/// 与 VaultPath 的格式天然兼容。
fn webdav_path_to_vault_path(dav_path: &dav_server::DavPath) -> VaultPath {
    VaultPath::new(dav_path.as_url_string())
}
```

`VaultPath::new()` 内部会自动执行规范化（处理 `..`、非法字符等），所以直接传入即可。

#### 4.3.4 关键并发模型

```text
   WebDAV Request (async, tokio)
          │
          ▼
   ┌──────────────────────────┐
   │ spawn_blocking {         │   ← 桥接异步 → 同步
   │   vault.lock()           │   ← 获取 Mutex 锁
   │   prepare_extraction_task│   ← 阶段 1: 数据库查询 (快速)
   │   drop(lock)             │   ← 立即释放锁
   │ }                        │
   └──────────┬───────────────┘
              │ ExtractionTask
              ▼
   ┌──────────────────────────┐
   │ spawn_blocking {         │
   │   execute_extraction_    │   ← 阶段 2: 解密 (慢速, 无需锁)
   │     task_standalone()    │
   │ }                        │
   └──────────┬───────────────┘
              │ 解密后的文件数据
              ▼
   返回给 WebDAV 客户端
```

**要点**：
- `rusqlite::Connection` 不是 `Send`，所以 `Vault` 不能跨线程传递。所有数据库操作必须在 `spawn_blocking` 内、持有 `Mutex` 锁时完成。
- 解密操作（阶段 2）使用 `execute_extraction_task_standalone(storage, task, dest_path)`，只需要 `&dyn StorageBackend`（它是 `Send + Sync`），不需要 `&Vault`，因此可以在释放锁后并行执行。
- `Arc<dyn StorageBackend>` 可以从 `vault.storage.clone()` 获取（`Arc` 克隆只增加引用计数），在释放 Vault 锁之前提前拿到。

---

### 4.4 `vfs/node.rs` — VaultDavFile

`DavFile` trait 代表一个已打开的文件句柄，必须支持读取（和可选的写入）。

#### 4.4.1 读取模式实现

```rust
/// 一个代表已打开的 Vault 文件的 WebDAV 文件句柄。
pub struct VaultDavFile {
    /// 解密后的文件内容。
    /// 小文件: 保存在内存中 (Vec<u8>)。
    /// 大文件: 保存在临时文件中。
    content: VaultFileContent,

    /// 当前读取位置。
    cursor: u64,

    /// 文件元数据 (大小、修改时间等)。
    metadata: VaultDavMetaData,
}

enum VaultFileContent {
    /// 内存中的文件内容 (适用于小文件，阈值建议 16MB)。
    InMemory(Vec<u8>),

    /// 临时文件 (适用于大文件)。
    TempFile(tokio::fs::File),
}
```

**解密策略**：

1. 在 `DavFileSystem::open()` 中获取 `ExtractionTask`。
2. 调用 `execute_extraction_task_standalone()` 将解密结果写入临时文件。
3. 将临时文件路径包装为 `VaultDavFile`。
4. `DavFile::read_bytes()` / `DavFile::seek()` 从临时文件读取。
5. 当 `VaultDavFile` 被 drop 时，临时文件自动清理（`tempfile` crate 的默认行为）。

#### 4.4.2 写入模式实现（阶段 5）

当 `read_only = false` 时，`DavFile` 还需支持写入：

1. `DavFileSystem::open()` 在写入模式下创建一个临时文件。
2. `DavFile::write_buf()` / `DavFile::write_bytes()` 将数据写入临时文件。
3. `DavFile::flush()` 完成时（或在某种 finalize 回调中），调用 `vault.add_file(temp_path, vault_path)` 将文件添加到 Vault。

---

### 4.5 `vfs/metadata.rs` — 元数据映射

Vault 中 `FileEntry` 的元数据需要映射为 WebDAV 属性（`DavMetaData`）。

#### 映射表

| Vault 元数据键 (常量定义在 `vavavult::common::constants`) | WebDAV 属性 | 说明 |
|---|---|---|
| `_vavavult_file_size` (`META_FILE_SIZE`) | `content-length` | 原始文件大小（字节） |
| `_vavavult_update_time` (`META_FILE_UPDATE_TIME`) | `last-modified` | 最后修改时间（RFC 3339） |
| `_vavavult_add_time` (`META_FILE_ADD_TIME`) | `creation-date` | 文件添加时间（RFC 3339） |
| `_vavavult_source_modified_time` (`META_SOURCE_MODIFIED_TIME`) | (可选) `getlastmodified` | 原始文件的修改时间 |

#### 辅助函数

```rust
use vavavult::file::FileEntry;
use vavavult::common::constants::*;
use chrono::DateTime;

/// 从 FileEntry 的 metadata 列表中提取指定 key 的值。
fn get_meta_value(entry: &FileEntry, key: &str) -> Option<String> {
    entry.metadata.iter()
        .find(|m| m.key == key)
        .map(|m| m.value.clone())
}

/// 将 FileEntry 转换为 WebDAV 文件大小。
/// 如果元数据中没有 file_size，返回 0。
pub fn get_content_length(entry: &FileEntry) -> u64 {
    get_meta_value(entry, META_FILE_SIZE)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// 将 FileEntry 转换为 WebDAV last-modified 时间戳。
/// 优先使用 source_modified_time，其次 update_time，最后 add_time。
pub fn get_last_modified(entry: &FileEntry) -> Option<DateTime<chrono::Utc>> {
    let time_str = get_meta_value(entry, META_SOURCE_MODIFIED_TIME)
        .or_else(|| get_meta_value(entry, META_FILE_UPDATE_TIME))
        .or_else(|| get_meta_value(entry, META_FILE_ADD_TIME));

    time_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// 将 FileEntry 转换为 WebDAV creation-date 时间戳。
pub fn get_creation_date(entry: &FileEntry) -> Option<DateTime<chrono::Utc>> {
    get_meta_value(entry, META_FILE_ADD_TIME)
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}
```

#### 目录元数据

对于目录（`DirectoryEntry::Directory`），没有对应的 `FileEntry`，需要返回合成的元数据：
- `content-length`: 0
- `is_dir`: true
- `last-modified`: 可使用 Vault 的 `_vavavult_update_time`（通过 `vault.get_vault_metadata()` 获取）

---

### 4.6 `auth.rs` — HTTP Basic Auth

作为 `hyper` 请求处理链中的一个前置检查层。

#### 实现逻辑

```text
请求到达
  │
  ├─ config.auth == None → 放行，继续处理 WebDAV 请求
  │
  └─ config.auth == Some(auth_config)
       │
       ├─ 请求包含 "Authorization: Basic <base64>" 头
       │    │
       │    ├─ 解码匹配 → 放行
       │    └─ 不匹配 → 返回 401 + WWW-Authenticate 头
       │
       └─ 请求不包含 Authorization 头
            └─ 返回 401 + WWW-Authenticate 头
```

#### 关键代码片段

```rust
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// 校验 HTTP Basic Auth。
/// 返回 true 表示认证成功，false 表示失败。
pub fn check_basic_auth(
    auth_header: Option<&str>,
    expected: &AuthConfig,
) -> bool {
    let header_value = match auth_header {
        Some(v) => v,
        None => return false,
    };

    // 1. 去掉 "Basic " 前缀
    let encoded = match header_value.strip_prefix("Basic ") {
        Some(e) => e,
        None => return false,
    };

    // 2. Base64 解码
    let decoded_bytes = match BASE64.decode(encoded) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let decoded_str = match String::from_utf8(decoded_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 3. 按 "username:password" 格式拆分并比较
    match decoded_str.split_once(':') {
        Some((user, pass)) => {
            user == expected.username && pass == expected.password
        }
        None => false,
    }
}
```

---

### 4.7 `server.rs` — 服务器启动与生命周期

#### 公共 API

```rust
use std::sync::{Arc, Mutex};
use vavavult::vault::Vault;

/// 服务器句柄，用于后台管理正在运行的 WebDAV 服务器。
pub struct ServerHandle {
    /// 用于通知服务器关闭的 oneshot 发送端。
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// 服务器任务的 JoinHandle。
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// 服务器实际绑定的地址 (用于日志和测试)。
    pub bound_addr: std::net::SocketAddr,
}

impl ServerHandle {
    /// 请求服务器优雅关闭。
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
    }
}

/// 启动 WebDAV 服务器并返回一个 ServerHandle。
///
/// 服务器在后台异步运行，调用者可通过 ServerHandle 控制其生命周期。
pub async fn start_webdav_server(
    vault: Arc<Mutex<Vault>>,
    config: MountConfig,
) -> Result<ServerHandle, MountError> {
    // 实现详见下方
    todo!()
}
```

#### 启动流程

```text
start_webdav_server(vault, config)
  │
  ├─ 1. 创建 VaultDavFs { vault, read_only: config.read_only }
  │
  ├─ 2. 创建 DavHandler::builder()
  │        .filesystem(Box::new(vault_dav_fs))
  │        .build_handler()
  │
  ├─ 3. 创建 oneshot channel (shutdown_tx, shutdown_rx)
  │
  ├─ 4. 绑定 TcpListener 到 config.bind_address:config.port
  │
  ├─ 5. tokio::spawn 异步任务 {
  │        loop {
  │          select! {
  │            conn = listener.accept() => {
  │              // 如果有 auth 配置，先检查 Authorization 头
  │              // 然后将请求交给 dav_handler 处理
  │            }
  │            _ = shutdown_rx => break  // 收到关闭通知
  │          }
  │        }
  │     }
  │
  └─ 6. 返回 ServerHandle { shutdown_tx, task_handle, bound_addr }
```

---

## 5. CLI 集成设计

### 5.1 AppState 扩展

```rust
// vavavult_cli/src/repl/state.rs
use std::sync::{Arc, Mutex};
use vavavult::vault::Vault;

pub struct AppState {
    pub active_vault: Option<Arc<Mutex<Vault>>>,
    /// 当前运行的 WebDAV 服务器句柄 (如果有)。
    pub mount_handle: Option<MountHandleWrapper>,
}

/// 包装 ServerHandle 和 tokio Runtime，使其可以在同步 REPL 中管理。
pub struct MountHandleWrapper {
    pub runtime: tokio::runtime::Runtime,
    pub handle: vavavult_mount::server::ServerHandle,
}
```

### 5.2 REPL 命令定义

```rust
// 在 vavavult_cli/src/cli.rs 的 ReplCommand 枚举中添加:

/// Start a WebDAV server to mount the vault
// 启动 WebDAV 服务器以挂载保险库
Mount {
    /// Listening port (default: 8080)
    // 监听端口 (默认: 8080)
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Bind address (default: 127.0.0.1)
    // 绑定地址 (默认: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Enable read-write mode (default is read-only)
    // 启用读写模式 (默认为只读)
    #[arg(long)]
    readwrite: bool,

    /// Enable HTTP Basic Auth (format: "username:password")
    // 启用 HTTP Basic Auth (格式: "username:password")
    #[arg(long, value_name = "USER:PASS")]
    auth: Option<String>,
},

/// Stop the running WebDAV server
// 停止正在运行的 WebDAV 服务器
Unmount,
```

### 5.3 Handler 实现要点

```text
handle_mount(app_state, args):
  1. 检查是否已有服务器在运行 → 如果是，提示先 unmount
  2. 解析 --auth 参数为 AuthConfig
  3. 构建 MountConfig
  4. 创建 tokio::runtime::Runtime (单独的异步运行时)
  5. 在 runtime 上调用 start_webdav_server(vault_arc.clone(), config)
  6. 将 ServerHandle + Runtime 存入 app_state.mount_handle
  7. 打印 "WebDAV server running at http://{bind}:{port}/"

handle_unmount(app_state):
  1. 取出 app_state.mount_handle → 如果为 None，提示没有运行中的服务器
  2. 调用 runtime.block_on(handle.shutdown())
  3. 将 app_state.mount_handle 设为 None
  4. 打印 "WebDAV server stopped."
```

---

## 6. Vault 公共 API 使用清单

以下列出 `vavavult_mount` 需要调用的所有 `Vault` 公共方法，**不需要访问任何 `pub(crate)` 或私有 API**：

### 只读操作（阶段 2-3）

| 方法 | 用途 |
|---|---|
| `vault.find_by_path(&VaultPath)` | 根据路径查找文件 → 返回 `QueryResult` |
| `vault.list_by_path(&VaultPath)` | 列出目录内容 → 返回 `Vec<DirectoryEntry>` |
| `vault.prepare_extraction_task(&VaultHash)` | 阶段 1: 准备文件提取任务 (需要锁) |
| `vault.execute_extraction_task(&ExtractionTask, &Path)` | 阶段 2: 执行解密 (可在锁外) |
| `vault.get_vault_metadata(&str)` | 获取 vault 级别的元数据 |
| `vault.get_file_count()` | 获取文件总数 (用于状态展示) |

也可使用 standalone 函数来完全避免持有 Vault 引用：

| 函数 | 用途 |
|---|---|
| `vavavult::vault::execute_extraction_task_standalone(storage, task, dest)` | 在无 `&Vault` 的情况下执行解密 |

### 写入操作（阶段 5）

| 方法 | 用途 |
|---|---|
| `vault.add_file(&Path, &VaultPath)` | 添加文件到 Vault |
| `vault.remove_file(&VaultHash)` | 删除文件 |
| `vault.move_file(&VaultHash, &VaultPath)` | 移动/重命名文件 |
| `vault.find_by_path(&VaultPath)` | 写入前检查是否已存在 |

### 需要提前持有的引用

由于解密操作（阶段 2）不需要 `&Vault`，但需要 `&dyn StorageBackend`：

```rust
// 在 Mutex 锁内完成
let vault_guard = self.vault.lock().unwrap();
let task = vault_guard.prepare_extraction_task(&hash)?;
let storage = vault_guard.storage.clone(); // Arc<dyn StorageBackend> clone
drop(vault_guard); // 立即释放锁

// 在锁外完成解密
vavavult::vault::execute_extraction_task_standalone(
    storage.as_ref(),
    &task,
    &temp_file_path,
)?;
```

**注意**：`vault.storage` 是 `pub` 字段（类型为 `Arc<dyn StorageBackend>`），可以直接访问。

---

## 7. 关键技术挑战与解决方案

### 7.1 `Vault` 非 `Send` 问题

**问题**：`rusqlite::Connection` 不是 `Send`，因此 `Vault` 不能在异步任务间传递。

**解决方案**：
- `Vault` 被包装在 `Arc<Mutex<Vault>>` 中。
- 所有数据库操作通过 `tokio::task::spawn_blocking(move || { ... })` 在阻塞线程中执行。
- 在 `spawn_blocking` 闭包内获取 `Mutex` 锁、执行操作、释放锁。
- `Arc<Mutex<Vault>>` 是 `Send + Sync`（`Mutex<T>` 对 `T: Send` 总是 `Send + Sync`），可以安全地 move 到 `spawn_blocking` 中。

### 7.2 大文件内存压力

**问题**：WebDAV `GET` 操作需要返回完整的解密文件内容。大文件（几百 MB 到 GB）不能全部放入内存。

**解决方案**：
- 始终将解密结果写入临时文件（`tempfile::NamedTempFile`）。
- 使用 `tokio::fs::File` 提供异步读取流给 WebDAV 客户端。
- 临时文件在 `VaultDavFile` 被 drop 时自动清理。
- 考虑缓存策略：对于短时间内的重复访问，可以缓存最近使用的临时文件（LRU），避免重复解密。这是一个**可选优化**，首个版本可以不实现。

### 7.3 并发读取性能

**问题**：多个客户端同时读取不同文件时，锁竞争可能成为瓶颈。

**解决方案**：
- 数据库查询（阶段 1）是快速操作，持锁时间极短。
- 解密（阶段 2）是慢速操作，完全在锁外执行。
- `StorageBackend` 的 `reader()` 方法返回独立的 `Box<dyn Read + Send>`，多个读取者之间互不干扰。
- 这意味着 N 个并发读取只会在数据库查询时短暂串行，解密过程完全并行。

### 7.4 写入的原子性（阶段 5）

**问题**：WebDAV `PUT` 操作可能上传大文件，不能长时间持有 Vault 的 `Mutex` 锁。

**解决方案**：
- 上传数据先写入临时文件（不需要锁）。
- 上传完成后，短暂获取锁调用 `vault.add_file(temp_path, vault_path)`。
- 如果上传中断，临时文件被自动清理，Vault 状态不受影响。

---

## 8. MIME 类型处理

WebDAV 客户端可能期望服务器返回 `Content-Type` 头。可以根据文件扩展名推断 MIME 类型：

- 使用 `mime_guess` crate（或简单的硬编码映射表）。
- 从 `VaultPath::file_name()` 获取文件名，提取扩展名。
- 未知扩展名返回 `application/octet-stream`。

此功能是**可选的增强**，`dav-server` 框架可能已有内置支持。

---

## 9. 测试策略

### 9.1 单元测试

位于 `vavavult_mount/tests/` 目录。

**测试辅助**：复用 `vavavult/tests/common/mod.rs` 中的 `TestContext` 模式，创建临时 Vault 并填入测试文件。

**测试用例**：

| 测试 | 验证内容 |
|---|---|
| `test_metadata_mapping` | `FileEntry` → `DavMetaData` 的正确性（大小、时间等） |
| `test_read_dir_root` | 根目录列表是否正确返回文件和子目录 |
| `test_read_dir_nested` | 嵌套目录列表的正确性 |
| `test_open_read_file` | 文件读取后内容是否与原始文件一致 |
| `test_open_nonexistent_file` | 不存在的路径是否返回 404 |
| `test_basic_auth_success` | 正确凭据是否能通过认证 |
| `test_basic_auth_failure` | 错误凭据是否被拒绝 |
| `test_readonly_rejects_write` | 只读模式下 PUT/DELETE 是否返回 403 |

### 9.2 集成测试

使用 `reqwest`（blocking 模式）作为 HTTP 客户端，发送 WebDAV 请求到实际启动的服务器：

```rust
#[test]
fn test_webdav_get_file() {
    // 1. 创建测试 Vault 并添加一个文件
    // 2. 启动 WebDAV 服务器 (绑定到 127.0.0.1:0 让 OS 分配端口)
    // 3. 使用 reqwest GET http://127.0.0.1:{port}/test.txt
    // 4. 验证响应状态码为 200
    // 5. 验证响应 body 与原始文件内容一致
    // 6. 关闭服务器
}
```

---

## 10. 未来扩展方向（不在当前计划内）

- **HTTPS 支持**：通过 `rustls` 或 `native-tls` 为 WebDAV 服务添加 TLS 加密。
- **缓存层**：实现 LRU 缓存，避免对频繁访问的文件重复解密。
- **ETag 支持**：使用 `VaultHash` 作为 ETag，支持条件请求 (`If-None-Match`)。
- **Range 请求**：支持 HTTP Range 头，允许客户端请求文件的部分内容（对视频播放等场景有用）。
- **多 Vault 挂载**：允许同时挂载多个 Vault 到不同的 URL 前缀下。