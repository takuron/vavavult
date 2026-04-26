# 已完成任务 (TODO Finished)

## 破坏性重构：分块加密架构

> 注意：此重构放弃向后兼容，已通过拦截旧有格式 API 和升级文件库版本号处理。所有的文件将强制使用分块加密算法。

### 阶段 1：底层存储抽象重构 (`vavavult/src/storage/`)
- [x] 修改 `StorageBackend` 抽象及底层实现（如 `local.rs`）：明确要求后端必须返回完全支持 `Read + Seek` 的 Reader 和 `Write + Seek` 的 Writer。

### 阶段 2：核心密码学层与 API 层重构 (`vavavult/src/crypto/chunked.rs` & `vavavult/src/vault/`)
- [x] 创建 `ChunkedEncryptor<W: Write + Seek>`：包装支持 Seek 的底层写入器，流式接收数据，满 4MB 缓冲后使用 AES-256-GCM 加密，并将 `密文 + Tag` 刷入底层写入器。实时计算原始哈希和加密哈希。
- [x] 创建 `ChunkedReader<R: Read + Seek>`：包装支持 Seek 的原始存储后端读取器。拦截 `seek` 调用，计算物理块边界 (`Header + N * (4MB + 16 bytes)`)，读取对应的块，使用 `Base IV ^ N` 解密并验证 Tag，内部维护 4MB 明文缓冲以提供字节级精确读取。
- [x] 彻底移除原有的连续流加密 (`stream_cipher.rs`) 及其所有桥接实现。
- [x] 新增 `ChunkedStorage` 包装类，用于在 `StorageBackend` 之上自动构造 `ChunkedEncryptor` 与 `ChunkedReader`。

### 阶段 3：API抽象重构
- [x] 修改 `Vault::encrypt_addition_task` 等所有写入桥梁：直接通过新包装的 `ChunkedEncryptor` 将数据写入支持 Seek 的 StorageWriter。
- [x] 重构解密/提取 API 等所有读取桥梁：新增 `Vault::open_file_for_read(hash) -> Result<impl Read + Seek + Send, Error>`，直接返回支持 $O(1)$ seek 的拉取式明文流，同时隐藏内部 `ChunkedReader` 类型。

## Vavavult Mount — 基于 WebDAV 的挂载与文件分享扩展

### 阶段 0：技术选型与依赖准备
- [x] 在 workspace `Cargo.toml` 的 `[workspace.dependencies]` 中添加 `dav-server`、`tokio`、`hyper`、`http-body-util`、`hyper-util` 等依赖
- [x] 更新 `vavavult_mount/Cargo.toml`，添加对 `vavavult` 核心库以及上述依赖的引用
- [x] 确认所有依赖版本兼容并能正常编译

### 阶段 1：错误类型与配置结构定义
- [x] 创建 `vavavult_mount/src/error.rs` — 定义 `MountError` 统一错误类型
- [x] 创建 `vavavult_mount/src/config.rs` — 定义 `MountConfig` 和 `AuthConfig` 结构体
- [x] 更新 `vavavult_mount/src/lib.rs` — 注册新模块并导出公共类型

### 阶段 2：虚拟文件系统层 — 只读实现 (核心)
- [x] 创建 `vavavult_mount/src/vfs/mod.rs` — 定义 `VaultDavFs` 结构体，持有 `Arc<Mutex<Vault>>`
- [x] 创建 `vavavult_mount/src/vfs/node.rs` — 实现 `VaultDavFile`（`DavFile` trait），处理文件解密与流式读取
- [x] 实现 `DavFileSystem::metadata()` — VaultPath 查询 + 元数据映射（`_vavavult_file_size` → content-length 等）
- [x] 实现 `DavFileSystem::read_dir()` — 调用 `vault.list_by_path()` 返回目录条目迭代器
- [x] 实现 `DavFileSystem::open()` — 基于两阶段 API（`prepare_extraction_task` → `execute_extraction_task_standalone`）完成解密读取
- [x] 针对 VFS 层编写单元测试

### 阶段 3：WebDAV 服务器启动与生命周期管理
- [x] 创建 `vavavult_mount/src/server.rs` — 实现 `start_webdav_server()` 和 `start_webdav_server_with_handle()`
- [x] 实现 `ServerHandle` 结构体（包含 `shutdown()` 方法，基于 `tokio::sync::oneshot` 通道）
- [x] 将 `VaultDavFs` 注入 `DavHandler`，通过 `hyper` 绑定地址并启动服务
- [x] 服务器启动时打印访问 URL 日志

### 阶段 4：可选的 HTTP Basic Auth
- [x] 创建 `vavavult_mount/src/auth.rs` — 实现 HTTP Basic Auth 中间件
- [x] 当 `MountConfig.auth` 为 `Some` 时，校验 `Authorization` 请求头
- [x] 认证失败返回 `401 Unauthorized` + `WWW-Authenticate: Basic realm="vavavult"`

### 阶段 5：写入支持（可选，受 `read_only` 配置控制）
- [x] 实现 `DavFileSystem::create_dir()` — 对 Vault 来说目录是隐式的，返回成功即可
- [x] 实现 `DavFile::write_all/write_bytes` (PUT) — 接收上传流 → 写入临时文件 → 调用 `vault.add_file()`
- [x] 实现 `DavFileSystem::remove_file()` (DELETE) — 调用 `vault.find_by_path()` → `vault.remove_file()`
- [x] 实现 `DavFileSystem::rename()` (MOVE) — 调用 `vault.find_by_path()` → `vault.move_file()`
- [x] 当 `read_only = true` 时，所有写入操作返回 `403 Forbidden`

### 阶段 6：CLI 集成
- [x] 在 `vavavult_cli/Cargo.toml` 中添加 `vavavult_mount` 和 `tokio` 依赖
- [x] 在 `vavavult_cli/src/cli.rs` 中添加 `Mount` / `Unmount` REPL 命令定义
- [x] 创建 `vavavult_cli/src/handlers/mount.rs` — 实现 mount/unmount handler
- [x] 更新 `vavavult_cli/src/handlers/mod.rs` — 注册新 handler
- [x] 更新 `vavavult_cli/src/repl/dispatcher.rs` — 添加 Mount/Unmount 分发逻辑
- [x] 扩展 `vavavult_cli/src/repl/state.rs` 中的 `AppState`，添加 `server_handle: Option<ServerHandle>` 字段

## 破坏性重构：实现多对一硬链接架构

> 注意：此重构放弃向后兼容，主要更改数据库结构，将原本存储在 `files` 表中的完整路径 `path` 移除。
> 引入类似于文件系统 inode 和 dentry 的结构，分离文件内容实体与目录/文件名映射，从而允许一个文件实体被多个路径引用。外部暴露的 `FileEntry` API 保持向下兼容。

### 阶段 1：底层数据库定义修改 (`vavavult/src/vault/create.rs`)
- [x] 移除 `files` 表的 `path` 字段。
- [x] 新增 `directories` 表，用于维护目录树结构 (`id`, `parent_id`, `name`)。
- [x] 新增 `file_entries` 表，用于维护文件映射/硬链接 (`id`, `directory_id`, `name`, `file_sha256sum`)。
- [x] 在新建保险库时，默认插入一条根目录记录作为挂载点。

### 阶段 2：核心查询与路径解析逻辑适配 (`vavavult/src/vault/query.rs` 等)
- [x] 实现路径解析辅助方法 `resolve_directory(path: &VaultPath)`，按层级解析目录返回 `directory_id`。
- [x] 重写 `find_by_path`，通过 `directories` 和 `file_entries` 表解析最终引用的文件，保持返回 `FileEntry` 结构体不变。
- [x] 重写 `find_by_hash`，按内容实体返回 `FileEntry`，不再依赖 `files.path`。
- [x] 新增 `list_paths_by_hash`，通过 CTE 向上追溯对应文件哈希的所有完整路径。
- [x] 重写 `list_directory`，支持同时从 `directories` 和 `file_entries` 获取子目录和文件列表。
- [x] 从 `FileEntry` 移除 `path` 属性；CLI/VFS 需要路径显示时暂时调用 `list_paths_by_hash` 并取第一条。

### 阶段 3：写入与更新逻辑适配 (`vavavult/src/vault/add.rs`, `remove.rs`, `update.rs`)
- [x] 修改 `commit_addition_tasks`，自动逐级创建缺失目录，并在 `file_entries` 中插入映射。利用新结构自动实现相同文件实体的去重复用。
- [x] 修改 `remove_file`，仅解除 `file_entries` 映射。当最后一条映射被解除时（引用计数清零），清理 `files` 表和物理存储。
- [x] 修改 `move_file` 和 `rename_file_inplace`，仅更新 `file_entries` 中的 `directory_id` 或 `name`，极速完成重命名/移动，避免操作底层文件实体。

### 阶段 4：测试与验证
- [x] 运行并修复回归测试（文件生命周期、重命名、重索引等）。
- [x] 新增多路径映射与引用计数删除的专项断言测试，确保文件实体在最后一次引用解除前不被误删。

## DB-first 元数据逻辑与修复边界

> 目标：路径/文件元数据操作默认只相信数据库，不因底层 `data/` 文件缺失失败。只有真正需要读取、写入或重写内容的操作（如 `add`、`extract`、`rekey`、`verify/fix`）才检查底层文件是否存在或完整；库外丢失文件等非预期状态由 `fix` 工具链处理。

- [x] 统一数据库路径不变量：保证数据库中不能同时存在 `/a` 文件和 `/a/` 目录；所有创建 `file_entries` 的入口共享同一套文件/目录冲突检查。
- [x] 查询逻辑降级为 DB-first：移除 `find/list/search` 等元数据查询中的 `storage.exists()` 强校验，让它们返回数据库路径映射、哈希和标签。
- [x] 限定内容操作的缺失报错边界：保留 `extract`、`rekey`、`verify_file_integrity`、`fix` 等内容相关流程中的底层文件存在性/完整性检查。
- [x] 调整删除语义：路径删除和 hash 删除以数据库清理为主，底层文件缺失时不阻断 DB 清理，并忽略底层文件已缺失的情况。
- [x] 打开库时启用外键约束：在 `open_vault` 成功打开/解密数据库连接后执行 `PRAGMA foreign_keys = ON`，确保级联删除在重开连接后仍生效。
- [x] 补齐回归测试：覆盖底层文件丢失后 `find/list/tag/move/remove_path` 可继续，`extract/rekey/verify` 明确失败，`fix` 可恢复或清理。
- [x] 同步架构文档：更新 `llm_readme.md` 中关于 DB-first 元数据逻辑、内容操作缺失报错边界和 fix 修复职责的说明。
