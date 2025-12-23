use crate::errors::CliError;
use crate::utils::is_hash_like;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use vavavult::common::hash::VaultHash;
use vavavult::file::VaultPath;
use vavavult::vault::Vault;

/// Main handler for the `verify` command.
/// It collects all files targeted for verification and dispatches them to either
/// a sequential or parallel execution handler.
//
// // `verify` 命令的主处理器。
// // 它收集所有待验证的目标文件，并将它们分发给
// // 顺序或并行执行的处理器。
pub fn handle_verify(
    vault: Arc<Mutex<Vault>>,
    targets: &[String],
    parallel: bool,
) -> Result<(), CliError> {
    println!("Collecting files to verify...");

    // This tuple will hold the list of (hash, path) for the files to be verified.
    // // 这个元组将持有待验证文件的 (哈希, 路径) 列表。
    let (files_to_verify, not_found) = {
        let vault_guard = vault.lock().unwrap();
        let mut hashes_to_check = HashSet::new();
        let mut not_found_targets = Vec::new();

        // First pass: collect all hashes from user targets.
        // // 第一遍：从用户目标中收集所有哈希。
        for target in targets {
            if is_hash_like(target) {
                if let Ok(hash) = VaultHash::from_str(target) {
                    hashes_to_check.insert(hash);
                } else {
                    not_found_targets.push(target.clone());
                }
            } else {
                let path = VaultPath::from(target.as_str());
                if path.is_dir() {
                    if let Ok(hashes) = vault_guard.list_all_recursive(&path) {
                        hashes_to_check.extend(hashes);
                    } else {
                        not_found_targets.push(target.clone());
                    }
                } else {
                    if let Ok(vavavult::vault::QueryResult::Found(entry)) =
                        vault_guard.find_by_path(&path)
                    {
                        hashes_to_check.insert(entry.sha256sum);
                    } else {
                        not_found_targets.push(target.clone());
                    }
                }
            }
        }

        // Second pass: build the final list of (hash, path) tuples.
        // A HashMap is used for quick lookups.
        // // 第二遍：构建最终的 (哈希, 路径) 元组列表。
        // // 使用 HashMap 以提高查找效率。
        let all_files = vault_guard.list_all().unwrap_or_default();
        let hash_to_path_map: HashMap<VaultHash, String> = all_files
            .into_iter()
            .map(|f| (f.sha256sum, f.path.to_string()))
            .collect();

        let files_to_verify: Vec<(VaultHash, String)> = hashes_to_check
            .into_iter()
            .filter_map(|h| hash_to_path_map.get(&h).map(|p| (h, p.clone())))
            .collect();

        (files_to_verify, not_found_targets)
    }; // Vault lock is released here // vault 锁在这里释放

    if !not_found.is_empty() {
        for target in not_found {
            eprintln!("Warning: Target not found or invalid: {}", target);
        }
    }

    if files_to_verify.is_empty() {
        println!("No valid files found to verify.");
        return Ok(());
    }

    println!("Verifying integrity of {} files...", files_to_verify.len());

    let (successes, failures) = if parallel {
        verify_parallel(vault, &files_to_verify)?
    } else {
        verify_sequential(vault, &files_to_verify)?
    };

    println!("\nVerification complete.");
    println!(
        "{} files checked. {} intact, {} issues found.",
        files_to_verify.len(),
        successes,
        failures
    );

    Ok(())
}

/// Verifies files sequentially in a single thread.
//
// // 在单线程中按顺序验证文件。
fn verify_sequential(
    vault: Arc<Mutex<Vault>>,
    files: &[(VaultHash, String)],
) -> Result<(usize, usize), CliError> {
    let total_count = files.len();
    let success_count = Arc::new(AtomicUsize::new(0));
    let pb = ProgressBar::new(total_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [Verifying] [{bar:40.cyan/blue}] {pos}/{len} {wide_msg}")
            .map_err(|e| CliError::Unexpected(e.to_string()))?
            .progress_chars("#>-"),
    );

    for (hash, path) in files {
        pb.set_message(path.clone());
        let vault_guard = vault.lock().unwrap();
        match vault_guard.verify_file_integrity(hash) {
            Ok(_) => {
                success_count.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                pb.println(format!("FAIL {} - {}", path, e));
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("Done");
    let successes = success_count.load(Ordering::SeqCst);
    let failures = total_count - successes;
    Ok((successes, failures))
}

/// Verifies files in parallel using a thread pool (Rayon).
//
// // 使用线程池 (Rayon) 并行验证文件。
fn verify_parallel(
    vault: Arc<Mutex<Vault>>,
    files: &[(VaultHash, String)],
) -> Result<(usize, usize), CliError> {
    let total_count = files.len();
    let success_count = Arc::new(AtomicUsize::new(0));
    let pb = ProgressBar::new(total_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [Verifying] [{bar:40.cyan/blue}] {pos}/{len}")
            .map_err(|e| CliError::Unexpected(e.to_string()))?
            .progress_chars("#>-"),
    );

    let storage = vault.lock().unwrap().storage.clone();

    files.into_par_iter().for_each(|(hash, path)| {
        match vavavult::vault::verify_encrypted_file_hash(storage.as_ref(), hash) {
            Ok(_) => {
                success_count.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                pb.println(format!("FAIL {} - {}", path, e));
            }
        }
        pb.inc(1);
    });

    pb.finish_with_message("Done");
    let successes = success_count.load(Ordering::SeqCst);
    let failures = total_count - successes;
    Ok((successes, failures))
}
