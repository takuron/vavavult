use crate::core::helpers::is_hash_like;
use crate::errors::CliError;
use crate::ui::prompt::confirm_action;
use indicatif::{ProgressBar, ProgressStyle};
use vavavult::extension::colorful_tag::COLORFUL_TAG_FEATURE;
use vavavult::file::VaultPath;
use vavavult::vault::{QueryPathResult, Vault};

struct TaggedFile {
    path: VaultPath,
}

/// 辅助函数：解析 tag 命令的路径目标。
fn parse_tag_target_path(target: &str) -> Result<VaultPath, CliError> {
    if is_hash_like(target) {
        return Err(CliError::InvalidTarget(
            "Tag commands now operate on vault paths only; hash targets are not accepted."
                .to_string(),
        ));
    }

    if !target.starts_with('/') {
        return Err(CliError::InvalidTarget(format!(
            "Tag target '{}' must be an absolute vault path starting with '/'.",
            target
        )));
    }

    Ok(VaultPath::from(target))
}

/// 辅助函数：根据路径获取所有受影响的文件。
fn get_files_to_tag(vault: &Vault, target: &str) -> Result<(Vec<TaggedFile>, String), CliError> {
    let vault_path = parse_tag_target_path(target)?;

    if vault_path.is_file() {
        // 1. 文件路径只影响该路径映射本身。
        match vault.find_by_path(&vault_path)? {
            QueryPathResult::Found(_) => {}
            QueryPathResult::NotFound => {
                return Err(CliError::EntryNotFound(
                    "File not found by path.".to_string(),
                ));
            }
        };
        let description = format!("file '{}'", vault_path);
        Ok((vec![TaggedFile { path: vault_path }], description))
    } else {
        // 2. 目录路径保留递归行为，但实际操作仍逐个落到文件路径映射上。
        let description = format!("directory '{}' (recursive)", vault_path);
        println!("Recursively scanning directory '{}'...", vault_path);
        let mut files = Vec::new();
        for file_path_entry in vault.list_all_recursive(&vault_path)? {
            if let QueryPathResult::Found(_) = vault.find_by_path(&file_path_entry.path)? {
                files.push(TaggedFile {
                    path: file_path_entry.path,
                });
            }
        }
        Ok((files, description))
    }
}

/// 主处理器：添加标签

pub fn handle_tag_add(vault: &mut Vault, target: &str, tags: &[String]) -> Result<(), CliError> {
    let (files_to_tag, target_description) = get_files_to_tag(vault, target)?;

    if files_to_tag.is_empty() {
        println!("No files found for {}. Nothing to tag.", target_description);

        return Ok(());
    }

    let tags_as_str: Vec<&str> = tags.iter().map(AsRef::as_ref).collect();

    let tag_list_str = format!("[{}]", tags_as_str.join(", "));

    let prompt = if files_to_tag.len() == 1 {
        format!("Add tags {} to {}?", tag_list_str, target_description)
    } else {
        format!(
            "Add tags {} to {} files from {}?",
            tag_list_str,
            files_to_tag.len(),
            target_description
        )
    };

    if !confirm_action(&prompt)? {
        println!("Operation cancelled.");

        return Ok(());
    }

    let total_count = files_to_tag.len();

    let pb = ProgressBar::new(total_count as u64);

    if total_count > 1 {
        pb.set_style(

            ProgressStyle::default_bar()

                .template(

                    "{spinner:.green} [Tagging] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}",

                )

                .map_err(|e| CliError::Unexpected(e.to_string()))?

                .progress_chars("#>-"),

        );
    }

    let mut success_count = 0;

    let mut fail_count = 0;

    for entry in &files_to_tag {
        match vault.add_tags(&entry.path, &tags_as_str) {
            Ok(_) => success_count += 1,

            Err(e) => {
                fail_count += 1;

                pb.println(format!("Failed to tag {}: {}", entry.path, e));
            }
        }

        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Tagging complete.");
    }

    if fail_count > 0 {
        println!(
            "Finished: {} files tagged, {} failed.",
            success_count, fail_count
        );
    } else {
        println!("Finished: {} file(s) tagged successfully.", success_count);
    }

    Ok(())
}

/// 主处理器：移除标签

pub fn handle_tag_remove(vault: &mut Vault, target: &str, tags: &[String]) -> Result<(), CliError> {
    let (files_to_tag, target_description) = get_files_to_tag(vault, target)?;

    if files_to_tag.is_empty() {
        println!(
            "No files found for {}. Nothing to modify.",
            target_description
        );

        return Ok(());
    }

    let tags_as_str: Vec<&str> = tags.iter().map(AsRef::as_ref).collect();

    let tag_list_str = format!("[{}]", tags_as_str.join(", "));

    let prompt = if files_to_tag.len() == 1 {
        format!("Remove tags {} from {}?", tag_list_str, target_description)
    } else {
        format!(
            "Remove tags {} from {} files from {}?",
            tag_list_str,
            files_to_tag.len(),
            target_description
        )
    };

    if !confirm_action(&prompt)? {
        println!("Operation cancelled.");

        return Ok(());
    }

    let total_count = files_to_tag.len();

    let pb = ProgressBar::new(total_count as u64);

    if total_count > 1 {
        pb.set_style(

            ProgressStyle::default_bar()

                .template(

                    "{spinner:.green} [Removing Tags] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}",

                )

                .map_err(|e| CliError::Unexpected(e.to_string()))?

                .progress_chars("#>-"),

        );
    }

    let mut success_count = 0;

    let mut files_failed = 0;

    for entry in &files_to_tag {
        let mut all_tags_removed_for_this_file = true;

        for tag in &tags_as_str {
            if let Err(e) = vault.remove_tag(&entry.path, tag) {
                pb.println(format!(
                    "Failed to remove tag '{}' from {}: {}",
                    tag, entry.path, e
                ));

                all_tags_removed_for_this_file = false;
            }
        }

        if all_tags_removed_for_this_file {
            success_count += 1;
        } else {
            files_failed += 1;
        }

        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Tag removal complete.");
    }

    if files_failed > 0 {
        println!(
            "Finished: Tags removed from {} files, {} files had errors.",
            success_count, files_failed
        );
    } else {
        println!(
            "Finished: Tags removed from {} file(s) successfully.",
            success_count
        );
    }

    Ok(())
}

/// 主处理器：清除所有标签
pub fn handle_tag_clear(vault: &mut Vault, target: &str) -> Result<(), CliError> {
    let (files_to_tag, target_description) = get_files_to_tag(vault, target)?;

    if files_to_tag.is_empty() {
        println!(
            "No files found for {}. Nothing to clear.",
            target_description
        );
        return Ok(());
    }

    let prompt = if files_to_tag.len() == 1 {
        format!(
            "Are you sure you want to clear ALL tags from {}?",
            target_description
        )
    } else {
        format!(
            "Are you sure you want to clear ALL tags from {} files from {}?",
            files_to_tag.len(),
            target_description
        )
    };

    if !confirm_action(&prompt)? {
        println!("Operation cancelled.");
        return Ok(());
    }

    let total_count = files_to_tag.len();
    let pb = ProgressBar::new(total_count as u64);
    if total_count > 1 {
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [Clearing Tags] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}",
                )
                .map_err(|e| CliError::Unexpected(e.to_string()))?
                .progress_chars("#>-"),
        );
    }

    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in &files_to_tag {
        match vault.clear_tags(&entry.path) {
            Ok(_) => success_count += 1,
            Err(e) => {
                fail_count += 1;
                pb.println(format!("Failed to clear tags for {}: {}", entry.path, e));
            }
        }
        if total_count > 1 {
            pb.inc(1);
        }
    }

    if total_count > 1 {
        pb.finish_with_message("Tag clearing complete.");
    }

    if fail_count > 0 {
        println!(
            "Finished: {} files cleared, {} failed.",
            success_count, fail_count
        );
    } else {
        println!("Finished: {} file(s) cleared successfully.", success_count);
    }
    Ok(())
}

/// 处理颜色设置命令
pub fn handle_tag_color(vault: &mut Vault, target: &str, color: &str) -> Result<(), CliError> {
    const ALLOWED_COLORS: &[&str] = &["red", "green", "yellow", "blue", "magenta", "cyan", "none"];

    let color_lower = color.to_lowercase();
    if !ALLOWED_COLORS.contains(&color_lower.as_str()) {
        return Err(CliError::InvalidCommand(format!(
            "Invalid color '{}'. Allowed: {}",
            color,
            ALLOWED_COLORS.join(", ")
        )));
    }

    if !vault.is_colorful_tag_enabled()? {
        println!(
            "Feature '{}' is not enabled. Enabling it now...",
            COLORFUL_TAG_FEATURE
        );
        vault.enable_colorful_tag()?;
        println!("Feature '{}' enabled.", COLORFUL_TAG_FEATURE);
    }

    let (files_to_tag, target_description) = get_files_to_tag(vault, target)?;

    if files_to_tag.is_empty() {
        println!(
            "No files found for {}. Nothing to color.",
            target_description
        );
        return Ok(());
    }

    let pb = ProgressBar::new(files_to_tag.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [Coloring] [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}",
            )
            .map_err(|e| CliError::Unexpected(e.to_string()))?
            .progress_chars("#>-"),
    );

    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in &files_to_tag {
        let result = if color_lower == "none" {
            vault.remove_path_color(&entry.path)
        } else {
            vault.set_path_color(&entry.path, &color_lower)
        };

        if let Err(e) = result {
            pb.println(format!("Failed to set color for {}: {}", entry.path, e));
            fail_count += 1;
        } else {
            success_count += 1;
        }
        pb.inc(1);
    }

    pb.finish_with_message("Color setting complete.");
    println!(
        "Finished: {} files processed, {} failed.",
        success_count, fail_count
    );
    Ok(())
}
