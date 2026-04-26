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
    *   `state.rs`: Defines `AppState`, which holds the active `Vault` instance wrapped in an `Arc<Mutex>`.

*   **`vavavult_cli::handlers`**
    *   **Path:** `vavavult_cli/src/handlers/`
    *   **Description:** Contains the implementation for each REPL command (e.g., `add.rs`, `extract.rs`, `list.rs`, `search.rs`). Each handler function receives the current `AppState` and the command arguments, calls the corresponding `vavavult` library functions, and uses the `ui` module to print the results.
    *   `move_cl.rs`: Implements `move`/`mv` by accepting only source vault paths (starting with `/`) and delegating to `Vault::move_path`; hash sources are rejected at the CLI layer.
    *   `move_cl.rs`: 通过仅接受以 `/` 开头的源保险库路径来实现 `move`/`mv`，并委托给 `Vault::move_path`；哈希源会在 CLI 层被拒绝。
    *   `rename.rs`: Implements `rename`/`ren` with the same source-path-only rule and delegates to `Vault::rename_path_inplace`.
    *   `rename.rs`: 以相同的仅源路径规则实现 `rename`/`ren`，并委托给 `Vault::rename_path_inplace`。
    *   `copy.rs`: Implements `copy`/`cp`/`cpoy` for file path copies by delegating to `Vault::copy_file_path`; hash sources are rejected at the CLI layer.
    *   `copy.rs`: 通过委托给 `Vault::copy_file_path` 实现文件路径复制命令 `copy`/`cp`/`cpoy`；哈希源会在 CLI 层被拒绝。

*   **`vavavult_cli::ui`**
    *   **Path:** `vavavult_cli/src/ui/`
    *   **Description:** Responsible for all console output.
    *   `printer.rs`: Contains functions for printing tables, lists, and other formatted output.
    *   `formatter.rs`: Provides helper functions to format data for display (e.g., file sizes, timestamps).
    *   `prompt.rs`: Handles user prompts and confirmation dialogs.

*   **`vavavult_cli::cli`**
    *   **Path:** `vavavult_cli/src/cli.rs`
    *   **Description:** Defines the command-line interface structure using `clap`. It specifies all available commands, subcommands, and their arguments.

### 3.3. Testing
*   **Path:** `vavavult_cli/tests/`
*   **Description:** Integration tests for the CLI are built using the `assert_cmd` and `predicates` crates, providing a robust way to test command execution and output.
*   **Framework:**
    *   `tests/common/mod.rs`: A shared helper module that provides utilities to simplify testing.
    *   `TestContext`: A key struct within the common module that creates a fully isolated environment for each test. `TestContext::new()` handles the creation of a temporary directory and a new vault inside it, ready for testing.
*   **Usage:** To write a new test, you typically start by creating a `TestContext`, then use `assert_cmd::Command` to run `vavavult` commands (either top-level or REPL commands via stdin), and finally use `predicates` to assert that the `stdout` or `stderr` contains the expected output.
