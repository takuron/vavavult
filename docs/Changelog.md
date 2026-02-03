## Vavavult v0.4.1

### English Changelog

#### Features:

- Implemented the `-f` (force) option for the `remove` command to ignore missing files during deletion.
- Added the `-y/--yes` flag to the `remove` command, separating the skip confirmation logic from the force logic.
- Added `vault.force_remove_file()` for idempotent file removal, which ensures a file entry is removed from both the database and storage while ignoring 'not found' errors.
- Introduced the `vault::fix_file` function to repair missing files in the vault.

#### Refactoring & Bug Fixes:

- Refactored `vault::fix_file` to use a single atomic transaction for replacing file records, enhancing data consistency.
- Fixed `vault::fix_file` by querying file metadata without storage validation, allowing successful repairs.
- Updated `vault::fix_file` to preserve the original `add_time` and custom metadata, while setting a new `update_time`.

#### Tests & Chores:

- Added tests for idempotency, inconsistent states, custom metadata preservation, and timestamp handling.
- Added standard documentation comments to the `FixError` enum.
- Marked the `rm -f` command as experimental and suppressed dead code warnings for unused validation functions.

### 中文更新日志

#### 新特性:

- 为 `remove` 命令实现了 `-f` (force) 选项，允许在删除时忽略丢失的文件。
- 为 `remove` 命令添加了 `-y/--yes` 标志，将跳过确认的逻辑与强制删除逻辑分离。
- 新增了用于幂等文件删除的 `vault.force_remove_file()` 函数，该函数可确保文件条目从数据库和存储中同时删除，并忽略“未找到”错误。
- 引入了 `vault::fix_file` 函数，用于修复保险库中丢失的文件。

#### 重构与问题修复:

- 重构了 `vault::fix_file`，使用单次原子事务来替换文件记录，提高了数据一致性。
- 修复了 `vault::fix_file` 函数，通过在没有存储验证的情况下查询文件元数据来实现预期修复。
- 更新了 `vault::fix_file` 逻辑，在设置新的 `update_time` 的同时，保留了原始的 `add_time` 和自定义元数据。

#### 测试与维护:

- 增加了针对幂等性、不一致状态、自定义元数据保留以及时间戳处理的测试用例。
- 为 `FixError` 枚举添加了标准的文档注释。
- 将 `rm -f` 标记为实验性功能，并抑制了未使用的验证函数的死代码警告。