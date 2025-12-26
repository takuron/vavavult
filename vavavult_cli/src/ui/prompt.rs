//! Functions for user interaction, like confirmation prompts.

use std::io;
use std::io::Write;

/// 向用户请求确认破坏性操作
pub fn confirm_action(prompt: &str) -> Result<bool, io::Error> {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    Ok(confirmation.trim().eq_ignore_ascii_case("y")
        || confirmation.trim().eq_ignore_ascii_case("yes"))
}
