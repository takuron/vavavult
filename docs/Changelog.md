## Vavavult v0.4.1

### English Changelog

#### Features:

- Added the `-y/--yes` flag to the `remove` command to skip confirmation prompts.
- Updated regular remove operations to clean database records while ignoring missing storage payloads.
- Introduced the `vault::fix_file` function to repair missing files in the vault.

#### Refactoring & Bug Fixes:

- Refactored `vault::fix_file` to use a single atomic transaction for replacing file records, enhancing data consistency.
- Fixed `vault::fix_file` by querying file metadata without storage validation, allowing successful repairs.
- Updated `vault::fix_file` to preserve the original `add_time` and custom metadata, while setting a new `update_time`.
- Updated the CLI `move`/`mv` command to accept only vault path sources and reject hash sources.
- Updated the CLI `rename`/`ren` command to accept only vault path sources and reject hash sources.
- Added the CLI `copy` command with `cp` and `cpoy` aliases for path-based file copies.

#### Tests & Chores:

- Added tests for idempotency, inconsistent states, custom metadata preservation, and timestamp handling.
- Added a CLI regression test covering path-only `move`/`mv` source handling.
- Added CLI regression tests covering path-only `rename` and `copy` source handling.
- Added standard documentation comments to the `FixError` enum.
- Suppressed dead code warnings for unused validation functions.

### 中文更新日志

#### 新特性:

- 为 `remove` 命令添加了 `-y/--yes` 标志，用于跳过确认提示。
- 更新普通删除逻辑，使其清理数据库记录并忽略已缺失的存储载荷。
- 引入了 `vault::fix_file` 函数，用于修复保险库中丢失的文件。

#### 重构与问题修复:

- 重构了 `vault::fix_file`，使用单次原子事务来替换文件记录，提高了数据一致性。
- 修复了 `vault::fix_file` 函数，通过在没有存储验证的情况下查询文件元数据来实现预期修复。
- 更新了 `vault::fix_file` 逻辑，在设置新的 `update_time` 的同时，保留了原始的 `add_time` 和自定义元数据。
- 更新 CLI 的 `move`/`mv` 命令，使其仅接受保险库路径作为源，并拒绝哈希源。
- 更新 CLI 的 `rename`/`ren` 命令，使其仅接受保险库路径作为源，并拒绝哈希源。
- 新增 CLI `copy` 命令，并提供 `cp` 和 `cpoy` 别名用于基于路径的文件复制。

#### 测试与维护:

- 增加了针对幂等性、不一致状态、自定义元数据保留以及时间戳处理的测试用例。
- 增加 CLI 回归测试，覆盖 `move`/`mv` 仅接受路径源的行为。
- 增加 CLI 回归测试，覆盖 `rename` 和 `copy` 仅接受路径源的行为。
- 为 `FixError` 枚举添加了标准的文档注释。
- 抑制了未使用的验证函数的死代码警告。
