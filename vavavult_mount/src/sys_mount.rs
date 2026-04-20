use crate::error::MountError;
use std::process::{Child, Command, Stdio};

/// Represents a mount handle. The mount will be automatically unmounted when the handle is dropped.
//
// // 表示挂载句柄。当句柄生命周期结束时，挂载将被自动卸载。
pub enum MountHandle {
    /// Native mount (e.g., `net use` on Windows, `mount_webdav` on macOS).
    /// These mounts are resident in the OS and require a specific command to unmount.
    //
    // // 本地原生挂载（如 Windows 的 `net use`，macOS 的 `mount_webdav`）。
    // // 这类挂载驻留于操作系统中，需要执行特定命令进行卸载。
    Native {
        /// The mount point (e.g., drive letter or path).
        //
        // // 挂载点（例如盘符或路径）。
        mount_point: String,
    },
    /// Relies on a third-party background process (e.g., `rclone mount` with `winfsp`).
    /// The mount ends when the process is killed.
    //
    // // 依赖第三方后台进程（例如 `rclone mount` 结合 `winfsp`）。
    // // 当进程被终止时，挂载即告结束。
    BackgroundProcess {
        /// The background child process.
        //
        // // 后台子进程。
        child: Child,
        /// The mount point.
        //
        // // 挂载点。
        mount_point: String,
    },
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        // 尝试卸载网络驱动器。
        let _ = self.unmount();
    }
}

impl MountHandle {
    /// Unmounts the mounted network drive.
    ///
    /// # Returns
    /// Returns an `Ok(())` on successful unmount, or a `MountError` on failure.
    //
    // // 卸载已挂载的网络驱动器。
    // //
    // // # 返回值
    // // 如果卸载成功，则返回 `Ok(())`，如果失败，则返回 `MountError`。
    pub fn unmount(&mut self) -> Result<(), MountError> {
        match self {
            MountHandle::Native { mount_point } => {
                // 调用系统原生的卸载方法。
                SystemMounter::unmount_native(mount_point)
            }
            MountHandle::BackgroundProcess { child, .. } => {
                // 杀死后台进程并等待其退出。
                let _ = child.kill();
                let _ = child.wait();
                Ok(())
            }
        }
    }
}

/// System-level utility class for mounting WebDAV as a local network drive across different platforms.
//
// // 系统级别的工具类，用于在不同平台上将 WebDAV 挂载为本地网络驱动器。
pub struct SystemMounter;

impl SystemMounter {
    /// Mounts a WebDAV URL to a local mount point (like a drive letter or directory).
    ///
    /// Allows the use of third-party support (e.g., `rclone` with `winfsp`) on systems where the native method is problematic.
    ///
    /// # Arguments
    /// * `url` - The WebDAV URL to mount.
    /// * `mount_point` - The target drive letter (Windows) or directory path.
    /// * `user` - Optional username for authentication.
    /// * `pass` - Optional password for authentication.
    ///
    /// # Errors
    /// Returns `MountError` if the mounting process fails.
    //
    // // 将 WebDAV URL 挂载到本地挂载点（如盘符或目录）。
    // //
    // // 对于原生方法存在问题的系统，允许使用第三方工具（如结合 `winfsp` 的 `rclone`）。
    // //
    // // # 参数
    // // * `url` - 要挂载的 WebDAV URL。
    // // * `mount_point` - 目标盘符（Windows）或目录路径。
    // // * `user` - 可选的认证用户名。
    // // * `pass` - 可选的认证密码。
    // //
    // // # 错误
    // // 如果挂载过程失败，则返回 `MountError`。
    pub fn mount(
        url: &str,
        mount_point: &str,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Result<MountHandle, MountError> {
        // 根据目标操作系统调用相应的挂载实现。
        #[cfg(target_os = "windows")]
        return Self::mount_windows(url, mount_point, user, pass);

        #[cfg(target_os = "macos")]
        return Self::mount_macos(url, mount_point, user, pass);

        #[cfg(target_os = "linux")]
        return Self::mount_linux(url, mount_point, user, pass);

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        return Err(MountError::ConfigError("Unsupported platform".to_string()));
    }

    #[cfg(target_os = "windows")]
    fn mount_windows(
        url: &str,
        mount_point: &str,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Result<MountHandle, MountError> {
        // 1. 优先尝试使用第三方支持工具 rclone（配合 winfsp），因为 Windows 的 WebClient 对 Basic Auth 和非标准端口支持较差。
        let mut rclone_cmd = Command::new("rclone");
        rclone_cmd.arg("mount");
        rclone_cmd.arg(":webdav:");
        rclone_cmd.arg(mount_point);
        rclone_cmd.arg(format!("--webdav-url={}", url));
        rclone_cmd.arg("--webdav-vendor=other");
        rclone_cmd.arg("--network-mode");

        if let Some(u) = user {
            rclone_cmd.arg(format!("--webdav-user={}", u));
        }
        if let Some(p) = pass {
            // 尝试混淆密码供 rclone 使用。
            if let Ok(obs) = Command::new("rclone").arg("obscure").arg(p).output() {
                if obs.status.success() {
                    let obscured_pass = String::from_utf8_lossy(&obs.stdout).trim().to_string();
                    rclone_cmd.arg(format!("--webdav-pass={}", obscured_pass));
                }
            }
        }

        rclone_cmd.stdout(Stdio::null());
        rclone_cmd.stderr(Stdio::null());

        // 如果能够成功拉起 rclone 进程，则返回后台挂载句柄。
        if let Ok(child) = rclone_cmd.spawn() {
            std::thread::sleep(std::time::Duration::from_millis(500));
            return Ok(MountHandle::BackgroundProcess {
                child,
                mount_point: mount_point.to_string(),
            });
        }

        // 2. 如果第三方工具不可用，则降级使用 Windows 原生的 net use 命令进行挂载。
        let mut cmd = Command::new("net");
        cmd.arg("use");
        cmd.arg(mount_point);
        cmd.arg(url);

        if let (Some(u), Some(p)) = (user, pass) {
            cmd.arg(format!("/user:{}", u));
            cmd.arg(p);
        }

        let output = cmd.output().map_err(MountError::IoError)?;

        if output.status.success() {
            Ok(MountHandle::Native {
                mount_point: mount_point.to_string(),
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(MountError::ConfigError(format!(
                "Failed to mount via net use: {}",
                stderr
            )))
        }
    }

    #[cfg(target_os = "windows")]
    fn unmount_native(mount_point: &str) -> Result<(), MountError> {
        // 调用 net use 命令的删除参数来卸载驱动器。
        let output = Command::new("net")
            .arg("use")
            .arg(mount_point)
            .arg("/delete")
            .arg("/y")
            .output()
            .map_err(MountError::IoError)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MountError::ConfigError(format!(
                "Failed to unmount: {}",
                stderr
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn mount_macos(
        url: &str,
        mount_point: &str,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Result<MountHandle, MountError> {
        // 1. 在 macOS 下优先尝试第三方工具 rclone（需要 macFUSE 或类似支持）。
        let mut rclone_cmd = Command::new("rclone");
        rclone_cmd.arg("mount");
        rclone_cmd.arg(":webdav:");
        rclone_cmd.arg(mount_point);
        rclone_cmd.arg(format!("--webdav-url={}", url));
        rclone_cmd.arg("--webdav-vendor=other");

        if let Some(u) = user {
            rclone_cmd.arg(format!("--webdav-user={}", u));
        }
        if let Some(p) = pass {
            if let Ok(obs) = Command::new("rclone").arg("obscure").arg(p).output() {
                if obs.status.success() {
                    let obscured_pass = String::from_utf8_lossy(&obs.stdout).trim().to_string();
                    rclone_cmd.arg(format!("--webdav-pass={}", obscured_pass));
                }
            }
        }

        rclone_cmd.stdout(Stdio::null());
        rclone_cmd.stderr(Stdio::null());

        if let Ok(child) = rclone_cmd.spawn() {
            std::thread::sleep(std::time::Duration::from_millis(500));
            return Ok(MountHandle::BackgroundProcess {
                child,
                mount_point: mount_point.to_string(),
            });
        }

        // 2. 降级尝试执行 macOS 的原生挂载命令 mount_webdav。
        let mut final_url = url.to_string();

        // 如果提供了用户名和密码，则将其拼接到 URL 中。
        if let (Some(u), Some(p)) = (user, pass) {
            if let Some(pos) = url.find("://") {
                let scheme = &url[..pos + 3];
                let rest = &url[pos + 3..];
                final_url = format!("{}{}:{}@{}", scheme, u, p, rest);
            }
        }

        // 尝试执行 macOS 的原生挂载命令 mount_webdav。
        let output = Command::new("mount_webdav")
            .arg("-i")
            .arg(&final_url)
            .arg(mount_point)
            .output()
            .map_err(MountError::IoError)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MountError::ConfigError(format!(
                "Failed to mount via mount_webdav: {}",
                stderr
            )));
        }
        Ok(MountHandle::Native {
            mount_point: mount_point.to_string(),
        })
    }

    #[cfg(target_os = "macos")]
    fn unmount_native(mount_point: &str) -> Result<(), MountError> {
        // 使用 umount 命令卸载。
        let output = Command::new("umount")
            .arg(mount_point)
            .output()
            .map_err(MountError::IoError)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MountError::ConfigError(format!(
                "Failed to unmount: {}",
                stderr
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mount_linux(
        url: &str,
        mount_point: &str,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Result<MountHandle, MountError> {
        // 1. 在 Linux 下优先尝试第三方工具 rclone。
        let mut rclone_cmd = Command::new("rclone");
        rclone_cmd.arg("mount");
        rclone_cmd.arg(":webdav:");
        rclone_cmd.arg(mount_point);
        rclone_cmd.arg(format!("--webdav-url={}", url));
        rclone_cmd.arg("--webdav-vendor=other");

        if let Some(u) = user {
            rclone_cmd.arg(format!("--webdav-user={}", u));
        }
        if let Some(p) = pass {
            if let Ok(obs) = Command::new("rclone").arg("obscure").arg(p).output() {
                if obs.status.success() {
                    let obscured_pass = String::from_utf8_lossy(&obs.stdout).trim().to_string();
                    rclone_cmd.arg(format!("--webdav-pass={}", obscured_pass));
                }
            }
        }

        rclone_cmd.stdout(Stdio::null());
        rclone_cmd.stderr(Stdio::null());

        if let Ok(child) = rclone_cmd.spawn() {
            std::thread::sleep(std::time::Duration::from_millis(500));
            return Ok(MountHandle::BackgroundProcess {
                child,
                mount_point: mount_point.to_string(),
            });
        }

        // 2. 降级使用 mount -t davfs 命令，这可能需要特权或 davfs2 的特定配置。
        let mut final_url = url.to_string();
        if let (Some(u), Some(p)) = (user, pass) {
            if let Some(pos) = url.find("://") {
                let scheme = &url[..pos + 3];
                let rest = &url[pos + 3..];
                final_url = format!("{}{}:{}@{}", scheme, u, p, rest);
            }
        }

        let output = Command::new("mount")
            .arg("-t")
            .arg("davfs")
            .arg(&final_url)
            .arg(mount_point)
            .output()
            .map_err(MountError::IoError)?;

        if output.status.success() {
            Ok(MountHandle::Native {
                mount_point: mount_point.to_string(),
            })
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(MountError::ConfigError(format!(
                "Failed to mount via mount: {}",
                stderr
            )))
        }
    }

    #[cfg(target_os = "linux")]
    fn unmount_native(mount_point: &str) -> Result<(), MountError> {
        // 使用 umount 命令卸载。
        let output = Command::new("umount")
            .arg(mount_point)
            .output()
            .map_err(MountError::IoError)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MountError::ConfigError(format!(
                "Failed to unmount: {}",
                stderr
            )));
        }
        Ok(())
    }
}
