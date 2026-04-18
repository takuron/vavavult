/// WebDAV server startup and lifecycle management.
///
/// This module provides `start_webdav_server()` which launches a WebDAV server
/// backed by a `VaultDavFs` instance. The server runs in a background tokio task
/// and can be gracefully shut down via the returned `ServerHandle`.
//
// // WebDAV 服务器启动与生命周期管理。
// //
// // 此模块提供 `start_webdav_server()`，用于启动由 `VaultDavFs` 实例支持的 WebDAV 服务器。
// // 服务器在后台 tokio 任务中运行，可通过返回的 `ServerHandle` 优雅关闭。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dav_server::DavHandler;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use vavavult::vault::Vault;

use crate::auth::check_basic_auth;
use crate::config::{AuthConfig, MountConfig};
use crate::error::MountError;
use crate::vfs::VaultDavFs;

/// A handle to a running WebDAV server.
///
/// Allows the caller to query the bound address and request a graceful shutdown.
/// Dropping this handle without calling `shutdown()` will leave the server running
/// until the tokio runtime is dropped.
//
// // 正在运行的 WebDAV 服务器的句柄。
// //
// // 允许调用者查询绑定地址并请求优雅关闭。
// // 在不调用 `shutdown()` 的情况下丢弃此句柄将使服务器持续运行，
// // 直到 tokio 运行时被丢弃。
pub struct ServerHandle {
    /// 用于通知服务器关闭的 oneshot 发送端。
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// 服务器任务的 JoinHandle。
    task_handle: Option<JoinHandle<()>>,
    /// The socket address the server is actually bound to.
    ///
    /// Useful for tests that bind to port 0 (OS-assigned port).
    //
    // // 服务器实际绑定的套接字地址。
    // //
    // // 对于绑定到端口 0（OS 分配端口）的测试非常有用。
    pub bound_addr: SocketAddr,
}

impl ServerHandle {
    /// Requests a graceful shutdown and waits for the server task to finish.
    ///
    /// # Returns
    /// Resolves once the server task has exited.
    //
    // // 请求优雅关闭并等待服务器任务完成。
    // //
    // // # 返回
    // // 服务器任务退出后解析。
    pub async fn shutdown(mut self) {
        // 发送关闭信号
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // 等待服务器任务退出
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Starts a WebDAV server backed by the given vault and returns a `ServerHandle`.
///
/// The server binds to `config.bind_address:config.port` and serves the vault
/// contents via WebDAV. If `config.auth` is set, HTTP Basic Auth is enforced on
/// every request.
///
/// The server runs in a background tokio task. Call `ServerHandle::shutdown()` to
/// stop it gracefully.
///
/// # Arguments
/// * `vault` - Shared reference to the vault to expose.
/// * `config` - Server configuration (address, port, auth, read-only flag).
///
/// # Returns
/// A `ServerHandle` with the actual bound address.
///
/// # Errors
/// Returns `MountError::IoError` if the TCP listener cannot be bound.
//
// // 启动由给定保险库支持的 WebDAV 服务器并返回 `ServerHandle`。
// //
// // 服务器绑定到 `config.bind_address:config.port` 并通过 WebDAV 提供保险库内容。
// // 如果设置了 `config.auth`，则对每个请求强制执行 HTTP Basic Auth。
// //
// // 服务器在后台 tokio 任务中运行。调用 `ServerHandle::shutdown()` 可优雅停止。
// //
// // # 参数
// // * `vault` - 要暴露的保险库的共享引用。
// // * `config` - 服务器配置（地址、端口、认证、只读标志）。
// //
// // # 返回
// // 包含实际绑定地址的 `ServerHandle`。
// //
// // # 错误
// // 如果无法绑定 TCP 监听器，则返回 `MountError::IoError`。
pub async fn start_webdav_server(
    vault: Arc<Mutex<Vault>>,
    config: MountConfig,
) -> Result<ServerHandle, MountError> {
    // 1. 构建 VaultDavFs 并注入 DavHandler
    let vfs = VaultDavFs::new(vault);
    let dav_handler = DavHandler::builder()
        .filesystem(Box::new(vfs))
        .build_handler();

    // 2. 绑定 TCP 监听器
    let bind_addr = format!("{}:{}", config.bind_address, config.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    let bound_addr = listener.local_addr()?;

    log::info!("WebDAV server listening on http://{}", bound_addr);

    // 3. 创建关闭通道
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    // 4. 克隆 auth 配置供任务使用
    let auth_config: Option<AuthConfig> = config.auth.clone();

    // 5. 启动后台服务器任务
    let task_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                // 接受新连接
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _peer_addr)) => {
                            let handler = dav_handler.clone();
                            let auth = auth_config.clone();
                            let io = TokioIo::new(stream);

                            // 每个连接在独立任务中处理
                            tokio::spawn(async move {
                                let service = service_fn(move |req: Request<Incoming>| {
                                    let handler = handler.clone();
                                    let auth = auth.clone();
                                    async move {
                                        handle_request(req, handler, auth).await
                                    }
                                });

                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    log::debug!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Accept error: {}", e);
                        }
                    }
                }
                // 收到关闭信号
                _ = &mut shutdown_rx => {
                    log::info!("WebDAV server shutting down");
                    break;
                }
            }
        }
    });

    Ok(ServerHandle {
        shutdown_tx: Some(shutdown_tx),
        task_handle: Some(task_handle),
        bound_addr,
    })
}

/// Handles a single HTTP request, optionally enforcing Basic Auth.
//
// // 处理单个 HTTP 请求，可选地强制执行 Basic Auth。
async fn handle_request(
    req: Request<Incoming>,
    handler: DavHandler,
    auth: Option<AuthConfig>,
) -> Result<Response<dav_server::body::Body>, std::convert::Infallible> {
    // 1. 如果配置了认证，先校验 Authorization 头
    if let Some(auth_config) = &auth {
        let auth_header = req
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        if !check_basic_auth(auth_header, auth_config) {
            // 认证失败，返回 401
            let response = Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", r#"Basic realm="vavavult""#)
                .body(dav_server::body::Body::empty())
                .unwrap();
            return Ok(response);
        }
    }

    // 2. 将请求转发给 DavHandler（Incoming 的错误类型已满足 StdError + Send + Sync + 'static）
    Ok(handler.handle(req).await)
}
