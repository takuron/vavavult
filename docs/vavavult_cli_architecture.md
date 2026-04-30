# Vavavult CLI Architecture

## 3. `vavavult_cli` - Command-Line Interface

A user-facing CLI application for interacting with `vavavult` vaults.

### 3.1. Entry Point: `main.rs`
*   **Path:** `vavavult_cli/src/main.rs`
*   **Description:** Parses top-level commands (`create`, `open`) using `clap`. Upon success, it initializes an `AppState` and enters an interactive REPL (Read-Eval-Print Loop).

### 3.2. Key Modules and Their Functions

*   **`vavavult_cli::repl`**
    *   **Path:** `vavavult_cli/src/repl/`
    *   **Description:** Implements the interactive shell.
    *   `mod.rs`: Contains the main `run_repl` loop which uses `rustyline` to read user input.
    *   `dispatcher.rs`: Takes the parsed command and delegates it to the appropriate handler in the `handlers` module.
    *   `state.rs`: Defines `AppState`, which holds the active `Vault` instance wrapped in an `Arc<Mutex>`, an optional `ServerHandle` and `MountHandle` for active mount sessions, and a tokio `Runtime` for async operations.

*   **`vavavult_cli::handlers`**
    *   **Path:** `vavavult_cli/src/handlers/`
    *   **Description:** Contains the implementation for each REPL command (e.g., `add.rs`, `extract.rs`, `list.rs`, `search.rs`). Each handler function receives the current `AppState` and the command arguments, calls the corresponding `vavavult` library functions, and uses the `ui` module to print the results.
    *   `move_cl.rs`: Implements `move`/`mv` by accepting only source vault paths (starting with `/`) and delegating to `Vault::move_path`; hash sources are rejected at the CLI layer. When moving a file to a directory destination, the original filename is appended automatically.
    *   `move_cl.rs`: 通过仅接受以 `/` 开头的源保险库路径来实现 `move`/`mv`，并委托给 `Vault::move_path`；哈希源会在 CLI 层被拒绝。将文件移动到目录目标时，会自动追加原文件名。
    *   `rename.rs`: Implements `rename`/`ren` with the same source-path-only rule and delegates to `Vault::rename_path_inplace`.
    *   `rename.rs`: 以相同的仅源路径规则实现 `rename`/`ren`，并委托给 `Vault::rename_path_inplace`。
    *   `copy.rs`: Implements `copy`/`cp`/`cpoy` for file path copies by delegating to `Vault::copy_file_path`; hash sources are rejected at the CLI layer. When copying a file to a directory destination, the original filename is appended automatically.
    *   `copy.rs`: 通过委托给 `Vault::copy_file_path` 实现文件路径复制命令 `copy`/`cp`/`cpoy`；哈希源会在 CLI 层被拒绝。将文件复制到目录目标时，会自动追加原文件名。
    *   `mount.rs`: Implements `mount` and `unmount` commands. `handle_mount` starts a WebDAV server via `vavavult_mount` and optionally mounts it to the OS via rclone. A soft-check for rclone existence is enforced at the start (detection order: system PATH → current directory); if rclone is not found, the command prints an error and exits without starting the server. `handle_unmount` tears down the system mount and stops the WebDAV server.
    *   `mount.rs`: 实现 `mount` 和 `unmount` 命令。`handle_mount` 通过 `vavavult_mount` 启动 WebDAV 服务器并可选择通过 rclone 挂载到操作系统。入口处强制执行 rclone 存在性软检查（检测顺序：系统 PATH → 当前文件夹）；如果未找到 rclone，则打印错误并退出，不启动服务器。`handle_unmount` 卸载系统挂载并停止 WebDAV 服务器。

*   **`vavavult_cli::ui`**
    *   **Path:** `vavavult_cli/src/ui/`
    *   **Description:** Responsible for all console output.
    *   `printer.rs`: Contains functions for printing tables, lists, and other formatted output.
    *   `formatter.rs`: Provides helper functions to format data for display (e.g., file sizes, timestamps).
    *   `prompt.rs`: Handles user prompts and confirmation dialogs.

*   **`vavavult_cli::cli`**
    *   **Path:** `vavavult_cli/src/cli.rs`
    *   **Description:** Defines the command-line interface structure using `clap`. It specifies all available commands, subcommands, and their arguments.
    *   Multi-file `add`, `extract`, and `verify` operations run in parallel by default; users can pass `--single-thread` to force the legacy sequential execution path.
    *   多文件 `add`、`extract` 和 `verify` 操作默认并行执行；用户可传入 `--single-thread` 强制使用旧的顺序单线程执行路径。

### 3.3. Testing
*   **Path:** `vavavult_cli/tests/`
*   **Description:** Integration tests for the CLI are built using the `assert_cmd` and `predicates` crates, providing a robust way to test command execution and output.
*   **Framework:**
    *   `tests/common/mod.rs`: A shared helper module that provides utilities to simplify testing.
    *   `TestContext`: A key struct within the common module that creates a fully isolated environment for each test. `TestContext::new()` handles the creation of a temporary directory and a new vault inside it, ready for testing.
*   **Usage:** To write a new test, you typically start by creating a `TestContext`, then use `assert_cmd::Command` to run `vavavult` commands (either top-level or REPL commands via stdin), and finally use `predicates` to assert that the `stdout` or `stderr` contains the expected output.
