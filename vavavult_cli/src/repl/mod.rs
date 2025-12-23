pub mod dispatcher;
pub mod state;

use crate::cli::ReplCommand;
use crate::errors::CliError;
use crate::repl::dispatcher::handle_repl_command;
use crate::repl::state::AppState;
use clap::Parser;
use rustyline::DefaultEditor;

pub fn run_repl(app_state: &mut AppState) -> Result<(), CliError> {
    let mut rl = DefaultEditor::new()?;

    while let Some(vault_arc) = &app_state.active_vault {
        let vault_name = vault_arc.lock().unwrap().config.name.clone();
        let prompt = format!("vavavult[{}]> ", vault_name);

        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;
                let args = shlex::split(line.as_str()).unwrap_or_default();
                if args.is_empty() {
                    continue;
                }

                match ReplCommand::try_parse_from(args) {
                    Ok(command) => {
                        if let Err(e) = handle_repl_command(command, app_state) {
                            eprintln!("Error: {}", e);
                        }
                    }
                    Err(e) => {
                        e.print()?;
                    }
                }
            }
            Err(_) => {
                if let Some(vault_arc) = app_state.active_vault.take() {
                    let vault_name = vault_arc.lock().unwrap().config.name.clone();
                    println!("\nClosing vault '{}'. Goodbye!", vault_name);
                }
                break;
            }
        }
    }
    Ok(())
}
