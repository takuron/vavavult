use std::sync::{Arc, Mutex};
// use tokio::runtime::Runtime;
use vavavult::vault::Vault;
// use vavavult_mount::{MountHandle, ServerHandle};

pub struct AppState {
    pub active_vault: Option<Arc<Mutex<Vault>>>,
    // pub server_handle: Option<ServerHandle>,
    // pub mount_handle: Option<MountHandle>,
    // pub rt: Runtime,
}

