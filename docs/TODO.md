# TODO List

*请参阅 [RoadMap.md](./RoadMap.md) 了解长期规划与暂未出具详细方案的宏观特性，或参阅 [TODO_finished.md](./TODO_finished.md) 了解已完成的任务历史。*

## 破坏性重构：分块加密架构

### 阶段 4：WebDAV 挂载层重构 (`vavavult_mount/src/vfs/node.rs`)
- [ ] 彻底移除旧版的 `ReadContent::Streaming` 状态机、`mpsc` 通道通信、`ReceiverReader`、`ChannelWriter` 以及 `tokio::task::spawn_blocking`。
- [ ] 将 `VaultDavFile` 状态变更为直接持有 `Vault::open_file_for_read` 返回的不透明 `Read + Seek` 明文流（必要时用 Mutex 包裹）。
- [ ] 重写 `DavFile::read_bytes` 和 `DavFile::seek`，直接调用该明文流，实现真正的零磁盘读写、零 CPU 浪费的瞬间随机访问。

### 阶段 5：系统挂载参数极简调优 (`vavavult_mount/src/sys_mount.rs`)
- [ ] 修改 `sys_mount.rs` 中所有平台 (`Windows`, `macOS`, `Linux`) 的 `rclone` 挂载参数：
  - [ ] 彻底关闭磁盘缓存：`--vfs-cache-mode=off`
  - [ ] 匹配分块读取粒度：`--vfs-read-chunk-size=4M`
  - [ ] 降低内存缓冲：`--buffer-size=8M`

### 阶段 6：验证与修复测试
- [ ] 为 `ChunkedReader` 和 `ChunkedEncryptor` 编写严格的单元测试（包括跨块 Seek、块内 Seek、EOF 逻辑、非法 MAC Tag 拒绝等）。
- [ ] 修复/移除 `vavavult` 及 `vavavult_mount` 中因为 API 破坏性变更而失效的测试用例。

---

## Vavavult Mount — 基于 WebDAV 的挂载与文件分享扩展

### 阶段 7：测试
- [ ] VFS 单元测试：元数据映射正确性、目录列表正确性、文件读取（解密）正确性
- [ ] 认证逻辑单元测试
- [ ] 集成测试：启动服务器 → HTTP 客户端发送 WebDAV 请求 → 验证响应内容
- [ ] CLI 集成测试：`mount` → 验证服务器启动 → `unmount` → 验证服务器停止
