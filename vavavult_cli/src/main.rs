use std::path::PathBuf;
use vavavult::vault::create_vault;

fn main() {
    let vault = create_vault(&*PathBuf::from("test"), "test");
}
