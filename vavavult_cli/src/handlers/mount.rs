use crate::errors::CliError;
use crate::repl::state::AppState;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use vavavult::vault::Vault;
use vavavult_mount::{MountConfig, SystemMounter, start_webdav_server};

/// 检测 rclone 是否存在于系统中。
///
/// 检测顺序：系统 PATH → 当前文件夹。
//
// // 检测 rclone 是否存在于系统中。
// //
// // 检测顺序：系统 PATH → 当前文件夹。
fn check_rclone_exists() -> bool {
    // 1. 检查系统 PATH 中的 rclone
    if std::process::Command::new("rclone")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return true;
    }

    // 2. 检查当前文件夹中的 rclone（Windows 上为 rclone.exe）
    let current_dir = match std::env::current_dir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let rclone_name = if cfg!(target_os = "windows") {
        "rclone.exe"
    } else {
        "rclone"
    };
    let local_path = current_dir.join(rclone_name);
    local_path.exists()
}

pub fn handle_mount(
    app_state: &mut AppState,
    vault: Arc<Mutex<Vault>>,
    port: u16,
    bind: &str,
    webdav_only: bool,
    read_only: bool,
    mount_point_opt: Option<String>,
) -> Result<(), CliError> {
    // 0. 软限制：仅在 rclone 存在时启用挂载功能（即使 WebDAV 服务器本身无需 rclone）
    if !check_rclone_exists() {
        println!("Error: rclone is not installed or not found in PATH.");
        println!("The mount feature requires rclone to function properly.");
        println!("Please install rclone from https://rclone.org/downloads/");
        println!("Or place the rclone binary in the current directory.");
        return Ok(());
    }

    if app_state.server_handle.is_some() || app_state.mount_handle.is_some() {
        println!("A WebDAV server or mount is already running.");
        println!("Please use 'unmount' first.");
        return Ok(());
    }

    let addr_str = format!("{}:{}", bind, port);
    let addr = SocketAddr::from_str(&addr_str).map_err(|_| {
        CliError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid bind address or port",
        ))
    })?;

    let config = MountConfig {
        bind_address: bind.to_string(),
        port,
        read_only,
        auth: None, // Optional auth can be added later if needed
        prefix: "/".to_string(),
    };

    println!("Starting WebDAV server at http://{}...", addr_str);
    let server_handle = app_state
        .rt
        .block_on(async { start_webdav_server(vault, config).await })
        .map_err(|e| {
            CliError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

    app_state.server_handle = Some(server_handle);

    if !webdav_only {
        let url = format!("http://{}", addr);
        let target_mount_point = if let Some(mp) = mount_point_opt {
            mp
        } else {
            // Automatic mount point assignment
            #[cfg(target_os = "windows")]
            {
                // Find a free drive letter. Very naive approach: Z:, Y:, X:, etc.
                let mut free_drive = String::from("Z:");
                for drive in (b'D'..=b'Z').rev() {
                    let d = format!("{}:\\", drive as char);
                    if !std::path::Path::new(&d).exists() {
                        free_drive = format!("{}:", drive as char);
                        break;
                    }
                }
                free_drive
            }
            #[cfg(target_os = "macos")]
            {
                let mount_dir = format!("/Volumes/vavavult_{}", port);
                std::fs::create_dir_all(&mount_dir).unwrap_or_default();
                mount_dir
            }
            #[cfg(target_os = "linux")]
            {
                let mount_dir = format!("/mnt/vavavult_{}", port);
                // Requires root to create dir in /mnt usually, but we try anyway.
                // Let's use a local dir in /tmp as fallback.
                if let Err(_) = std::fs::create_dir_all(&mount_dir) {
                    let fallback_dir = format!("/tmp/vavavult_{}", port);
                    let _ = std::fs::create_dir_all(&fallback_dir);
                    fallback_dir
                } else {
                    mount_dir
                }
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            {
                println!(
                    "Automatic mount is not supported on this OS. Starting WebDAV server only."
                );
                return Ok(());
            }
        };

        println!("Mounting WebDAV to {}...", target_mount_point);
        match SystemMounter::mount(&url, &target_mount_point, None, None) {
            Ok(handle) => {
                println!("Successfully mounted to {}", target_mount_point);
                app_state.mount_handle = Some(handle);
            }
            Err(e) => {
                println!("Failed to mount automatically: {}", e);
                println!("WebDAV server is still running at {}", url);
            }
        }
    } else {
        println!("WebDAV server started successfully. Skipping system mount.");
    }

    Ok(())
}

pub fn handle_unmount(app_state: &mut AppState) -> Result<(), CliError> {
    if let Some(mut mount_handle) = app_state.mount_handle.take() {
        println!("Unmounting drive...");
        if let Err(e) = mount_handle.unmount() {
            println!("Warning: Failed to unmount drive cleanly: {}", e);
        } else {
            println!("Successfully unmounted drive.");
        }
    } else {
        println!("No active system mount found.");
    }

    if let Some(_server_handle) = app_state.server_handle.take() {
        // Since ServerHandle uses oneshot channel for shutdown on Drop,
        // simply dropping it will initiate shutdown.
        println!("Stopping WebDAV server...");
    } else {
        println!("No active WebDAV server found.");
    }

    Ok(())
}
