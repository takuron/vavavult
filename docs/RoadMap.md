# Vavavult RoadMap (路线图)

本文档记录了 Vavavult 项目的宏观演进方向以及暂未规划详细方案的特性拓展目标。
已有完整实现方案的具体任务请参阅 [TODO.md](./TODO.md)；历史完成记录请参阅 [TODO_finished.md](./TODO_finished.md)。

## 核心架构演进 (Core Architecture Evolution)
- [ ] 分块加密架构: 将底层存储引擎迁移至 4MB 分块加密，支持 O(1) 随机访问并降低内存占用 (具体实施阶段见 TODO)
- [x] 多对一硬链接与 DB-first 元数据: 重构数据库实现 inode 机制及去重复用，元数据操作全面以数据库记录为准

## 生态与扩展 (Ecosystem & Extensions)
- [ ] WebDAV 挂载扩展 (`vavavult_mount`): 内置 WebDAV 服务器，支持零落盘读取和受控写入，映射为本地网络驱动器 (具体实施阶段见 TODO)
- [ ] 开发者接口: 提供对存储库更底层的操作（例如执行SQL），便于外部基于 Core 构建上层应用
- [ ] 数据库救援接口: 整合目前的 fix 等方法，专门修复数据库损坏、索引丢失等极端错误
- [ ] 额外功能包: 提供一个新的 feature 供项目拓展，整合更多高级功能（如数据同步、云端存储后端支持等）
