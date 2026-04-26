use crate::cli::{ReplCommand, TagCommand, VaultCommand};
use crate::errors::CliError;
use crate::handlers;
use crate::repl::state::AppState;
use std::sync::Arc;

/// REPL 命令处理器
pub fn handle_repl_command(command: ReplCommand, app_state: &mut AppState) -> Result<(), CliError> {
    // 检查 vault 是否存在。如果命令是 Exit 或 Close，它们会使 active_vault 变为 None，
    // 从而自然地终止 run_repl 中的 while let 循环。
    let vault_arc = {
        let Some(vault) = app_state.active_vault.as_ref() else {
            return Ok(());
        };
        Arc::clone(vault)
    };

    match command {
        ReplCommand::Add {
            local_path,
            path,
            name,
            parallel,
            no_duplicate_files,
        } => {
            handlers::add::handle_add(
                Arc::clone(&vault_arc),
                &local_path,
                path,
                name,
                parallel,
                !no_duplicate_files,
            )?;
        }
        ReplCommand::List {
            path,
            long,
            recursive,
        } => {
            let vault = vault_arc.lock().unwrap();
            handlers::list::handle_list(&vault, path, long, recursive)?;
        }
        ReplCommand::Search { keyword, long } => {
            let vault = vault_arc.lock().unwrap();
            handlers::search::handle_search(&vault, &keyword, long)?;
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
                Arc::clone(&vault_arc),
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
            yes,
        } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::remove::handle_remove(&mut vault, &target, recursive, yes)?;
        }
        ReplCommand::Move {
            source_path,
            destination,
        } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::move_cl::handle_move(&mut vault, &source_path, destination)?;
        }
        ReplCommand::Copy {
            source_path,
            destination,
        } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::copy::handle_copy(&mut vault, &source_path, destination)?;
        }
        ReplCommand::Rename {
            source_path,
            new_name,
        } => {
            let mut vault = vault_arc.lock().unwrap();
            handlers::rename::handle_file_rename(&mut vault, &source_path, &new_name)?;
        }
        ReplCommand::Verify { targets, parallel } => {
            handlers::verify::handle_verify(Arc::clone(&vault_arc), &targets, parallel)?;
        }
        /*
        ReplCommand::Mount {
            port,
            bind,
            webdav_only,
            read_only,
            mount_point,
        } => {
            handlers::mount::handle_mount(
                app_state,
                Arc::clone(&vault_arc),
                port,
                &bind,
                webdav_only,
                read_only,
                mount_point,
            )?;
        }
        ReplCommand::Unmount => {
            handlers::mount::handle_unmount(app_state)?;
        }
        */
        ReplCommand::Vault(vault_command) => match vault_command {
            VaultCommand::Rename { new_name } => {
                let mut vault = vault_arc.lock().unwrap();

                handlers::vault::handle_vault_rename(&mut vault, &new_name)?;
            }
            VaultCommand::Status => {
                let vault = vault_arc.lock().unwrap();
                handlers::vault::handle_status(&vault)?;
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
