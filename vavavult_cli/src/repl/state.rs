use std::sync::{Arc, Mutex};
use vavavult::vault::Vault;

pub struct AppState {
    pub active_vault: Option<Arc<Mutex<Vault>>>,
}
