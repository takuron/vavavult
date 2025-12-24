use crate::cli::{ReplCommand, TagCommand, VaultCommand};
use crate::errors::CliError;
use crate::handlers;
use crate::repl::state::AppState;
use std::sync::Arc;

/// REPL 命令处理器
pub fn handle_repl_command(command: ReplCommand, app_state: &mut AppState) -> Result<(), CliError> {
    // 检查 vault 是否存在。如果命令是 Exit 或 Close，它们会使 active_vault 变为 None，
    // 从而自然地终止 run_repl 中的 while let 循环。
    let Some(vault_arc) = app_state.active_vault.as_mut() else {
        return Ok(());
    };

    match command {
        ReplCommand::Add {
            local_path,
            path,
            name,
            parallel,
        } => {
            handlers::add::handle_add(Arc::clone(vault_arc), &local_path, path, name, parallel)?;
        }
        ReplCommand::List {
            path,
            long,
            recursive,
        } => {
            let vault = vault_arc.lock().unwrap();
            // 1. 从 handler 获取数据
            let (list_result, target_path) = handlers::list::handle_list(&vault, path, recursive)?;

            // 2. 获取显示选项
            let colors_enabled = vault.is_feature_enabled("colorfulTag").unwrap_or(false);

            // 3. 将数据传递给 printer
            crate::ui::printer::print_list_result(&list_result, long, colors_enabled, &target_path);
        }
        ReplCommand::Search { keyword, long } => {
            let vault = vault_arc.lock().unwrap();
            let found_files = handlers::search::handle_search(&vault, &keyword)?;

            if found_files.is_empty() {
                println!("No files found matching '{}' (in name or tags).", keyword);
            } else {
                println!(
                    "Found {} file(s) matching '{}' (in name or tags):",
                    found_files.len(),
                    keyword
                );

                let colors_enabled = vault.is_feature_enabled("colorfulTag").unwrap_or(false);

                if long {
                    for file in &found_files {
                        crate::ui::printer::print_file_details(file, colors_enabled);
                    }
                    if !found_files.is_empty() {
                        println!("----------------------------------------");
                    }
                } else {
                    for file in &found_files {
                        crate::ui::printer::print_recursive_file_item(file, colors_enabled);
                    }
                }
            }
        }
        ReplCommand::Open { target } => {
            let vault = vault_arc.lock().unwrap();
            handlers::open::handle_open(&vault, &target)?;
        }
        ReplCommand::Extract {
            target,
            destination,
            output_name,
            non_recursive,
            delete,
            parallel,
        } => {
            handlers::extract::handle_extract(
                Arc::clone(vault_arc),
                target,
                destination,
                output_name,
                non_recursive,
                delete,
                parallel,
            )?;
        }
        ReplCommand::Remove {
            target,
            recursive,
            force,
        } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::remove::handle_remove(&mut vault, &target, recursive, force)?;
        }
        ReplCommand::Move {
            target,
            destination,
        } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::move_cl::handle_move(&mut vault, &target, destination)?;
        }
        ReplCommand::Rename { target, new_name } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::rename::handle_file_rename(&mut vault, &target, &new_name)?;
        }
        ReplCommand::Verify { targets, parallel } => {
            handlers::verify::handle_verify(Arc::clone(vault_arc), &targets, parallel)?;
        }
        ReplCommand::Vault(vault_command) => match vault_command {
            VaultCommand::Rename { new_name } => {
                let mut vault = vault_arc.lock().unwrap();

                handlers::vault::handle_vault_rename(&mut vault, &new_name)?;
            }
            VaultCommand::Status => {
                let vault = vault_arc.lock().unwrap();
                let status = handlers::vault::handle_status(&vault)?;
                crate::ui::printer::print_status(&status);
            }
        },
        ReplCommand::Tag(tag_command) => {
            let mut vault = vault_arc.lock().unwrap();
            match tag_command {
                TagCommand::Add { target, tags } => {
                    handlers::tag::handle_tag_add(&mut vault, &target, &tags)?;
                }
                TagCommand::Remove { target, tags } => {
                    handlers::tag::handle_tag_remove(&mut vault, &target, &tags)?;
                }
                TagCommand::Clear { target } => {
                    handlers::tag::handle_tag_clear(&mut vault, &target)?;
                }
                TagCommand::Color { target, color } => {
                    handlers::tag::handle_tag_color(&mut vault, &target, &color)?;
                }
            }
        }
        ReplCommand::Exit => {
            let vault_name = app_state
                .active_vault
                .take()
                .unwrap()
                .lock()
                .unwrap()
                .config
                .name
                .clone();
            println!("Closing vault '{}'. Goodbye!", vault_name);
        }
    }
    Ok(())
}
