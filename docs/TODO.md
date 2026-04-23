# TODO List

## Vavavult Core

- [ ] 开发者接口:提供对存储库更底层的操作（例如执行SQL）
- [ ] 数据库救援接口：整合目前的fix等方法，专门修复数据库错误
- [ ] 额外功能包：提供一个新的feature来整合更多功能

---

## Vavavult Mount — 基于 WebDAV 的挂载与文件分享扩展

> 对应 crate: `vavavult_mount`
> 架构详情请参阅 [vavavult_mount_architecture.md](./vavavult_mount_architecture.md)

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

### 阶段 7：测试
- [ ] VFS 单元测试：元数据映射正确性、目录列表正确性、文件读取（解密）正确性
- [ ] 认证逻辑单元测试
- [ ] 集成测试：启动服务器 → HTTP 客户端发送 WebDAV 请求 → 验证响应内容
- [ ] CLI 集成测试：`mount` → 验证服务器启动 → `unmount` → 验证服务器停止
