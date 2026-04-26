use crate::file::VaultPath;
use crate::vault::{QueryError, QueryPathResult, TagError, UpdateError, Vault};

/// The vault feature name used by the colorful tag extension.
///
/// This feature gates all path color operations. A vault must explicitly enable
/// this feature before color tags can be added or removed through the extension API.
//
// // colorful tag 扩展使用的保险库功能名称。
// //
// // 该功能控制所有路径颜色操作。保险库必须显式启用此功能后，
// // 才能通过扩展 API 添加或删除颜色标签。
pub const COLORFUL_TAG_FEATURE: &str = "colorfulTag";

const COLOR_TAG_PREFIX: &str = "_color:";
const ALLOWED_COLORS: &[&str] = &["red", "green", "yellow", "blue", "magenta", "cyan"];

/// Defines errors that can occur during colorful tag extension operations.
///
/// These errors cover feature gating, color validation, database queries, and
/// path-level tag mutations.
//
// // 定义 colorful tag 扩展操作期间可能发生的错误。
// //
// // 这些错误覆盖功能开关、颜色校验、数据库查询以及路径级标签修改。
#[derive(Debug, thiserror::Error)]
pub enum ColorfulTagError {
    /// The colorful tag feature is not enabled for the vault.
    //
    // // 当前保险库未启用 colorful tag 功能。
    #[error("Feature '{0}' is not enabled for this vault.")]
    FeatureDisabled(&'static str),

    /// The requested color is not supported.
    //
    // // 请求的颜色不受支持。
    #[error("Invalid color '{color}'. Allowed: {allowed}.")]
    InvalidColor { color: String, allowed: String },

    /// A vault query failed.
    //
    // // 保险库查询失败。
    #[error("Query error: {0}")]
    Query(#[from] QueryError),

    /// A tag mutation failed.
    //
    // // 标签修改失败。
    #[error("Tag error: {0}")]
    Tag(#[from] TagError),

    /// A feature update failed.
    //
    // // 功能更新失败。
    #[error("Update error: {0}")]
    Update(#[from] UpdateError),
}

impl Vault {
    /// Checks whether the colorful tag extension is enabled.
    ///
    /// # Returns
    /// `Ok(true)` when `colorfulTag` is enabled, otherwise `Ok(false)`.
    ///
    /// # Errors
    /// Returns `QueryError` if the vault feature metadata cannot be queried.
    //
    // // 检查 colorful tag 扩展是否已启用。
    // //
    // // # 返回
    // // 如果 `colorfulTag` 已启用则返回 `Ok(true)`，否则返回 `Ok(false)`。
    // //
    // // # 错误
    // // 如果无法查询保险库功能元数据，则返回 `QueryError`。
    pub fn is_colorful_tag_enabled(&self) -> Result<bool, QueryError> {
        self.is_feature_enabled(COLORFUL_TAG_FEATURE)
    }

    /// Enables the colorful tag extension for this vault.
    ///
    /// This only enables the feature flag. It does not add or change any file
    /// path color tags by itself.
    ///
    /// # Errors
    /// Returns `UpdateError` if the feature flag cannot be persisted.
    //
    // // 为当前保险库启用 colorful tag 扩展。
    // //
    // // 该方法只启用功能标记，本身不会新增或修改任何文件路径颜色标签。
    // //
    // // # 错误
    // // 如果无法持久化功能标记，则返回 `UpdateError`。
    pub fn enable_colorful_tag(&mut self) -> Result<(), UpdateError> {
        self.enable_feature(COLORFUL_TAG_FEATURE)
    }

    /// Sets a display color tag for a specific file path.
    ///
    /// The operation is path-scoped. It removes any existing `_color:*` tag from
    /// the target path and then adds `_color:<color>`.
    ///
    /// # Arguments
    /// * `path` - The vault file path whose color should be changed.
    /// * `color` - One of `red`, `green`, `yellow`, `blue`, `magenta`, or `cyan`.
    ///
    /// # Errors
    /// Returns `ColorfulTagError::FeatureDisabled` when `colorfulTag` is not enabled.
    /// Returns `ColorfulTagError::InvalidColor` for unsupported colors.
    /// Returns other `ColorfulTagError` variants for query or tag mutation failures.
    //
    // // 为特定文件路径设置显示颜色标签。
    // //
    // // 该操作以路径为作用域。它会先移除目标路径上已有的 `_color:*` 标签，
    // // 然后添加 `_color:<color>`。
    // //
    // // # 参数
    // // * `path` - 要修改颜色的保险库文件路径。
    // // * `color` - `red`、`green`、`yellow`、`blue`、`magenta` 或 `cyan` 之一。
    // //
    // // # 错误
    // // 当 `colorfulTag` 未启用时返回 `ColorfulTagError::FeatureDisabled`。
    // // 对不支持的颜色返回 `ColorfulTagError::InvalidColor`。
    // // 对查询或标签修改失败返回其他 `ColorfulTagError` 变体。
    pub fn set_path_color(
        &mut self,
        path: &VaultPath,
        color: &str,
    ) -> Result<(), ColorfulTagError> {
        self.ensure_colorful_tag_enabled()?;
        let color_lower = color.to_lowercase();
        if !ALLOWED_COLORS.contains(&color_lower.as_str()) {
            return Err(ColorfulTagError::InvalidColor {
                color: color.to_string(),
                allowed: ALLOWED_COLORS.join(", "),
            });
        }

        self.remove_existing_color_tags(path)?;
        self.add_tag(path, &format!("{}{}", COLOR_TAG_PREFIX, color_lower))?;
        Ok(())
    }

    /// Removes the display color tag from a specific file path.
    ///
    /// The operation is path-scoped and only removes tags whose names start with
    /// `_color:`.
    ///
    /// # Arguments
    /// * `path` - The vault file path whose color tag should be removed.
    ///
    /// # Errors
    /// Returns `ColorfulTagError::FeatureDisabled` when `colorfulTag` is not enabled.
    /// Returns other `ColorfulTagError` variants for query or tag mutation failures.
    //
    // // 从特定文件路径删除显示颜色标签。
    // //
    // // 该操作以路径为作用域，并且只删除名称以 `_color:` 开头的标签。
    // //
    // // # 参数
    // // * `path` - 要移除颜色标签的保险库文件路径。
    // //
    // // # 错误
    // // 当 `colorfulTag` 未启用时返回 `ColorfulTagError::FeatureDisabled`。
    // // 对查询或标签修改失败返回其他 `ColorfulTagError` 变体。
    pub fn remove_path_color(&mut self, path: &VaultPath) -> Result<(), ColorfulTagError> {
        self.ensure_colorful_tag_enabled()?;
        self.remove_existing_color_tags(path)
    }

    /// Gets the display color configured for a specific file path.
    ///
    /// The operation is path-scoped and returns the first `_color:<color>` tag
    /// found on the target path. If the path has no color tag, it returns `Ok(None)`.
    ///
    /// # Arguments
    /// * `path` - The vault file path whose color should be read.
    ///
    /// # Returns
    /// `Ok(Some(color))` when a color tag exists, or `Ok(None)` when no color is set.
    ///
    /// # Errors
    /// Returns `ColorfulTagError::FeatureDisabled` when `colorfulTag` is not enabled.
    /// Returns other `ColorfulTagError` variants for query failures.
    //
    // // 获取特定文件路径配置的显示颜色。
    // //
    // // 该操作以路径为作用域，并返回目标路径上找到的第一个 `_color:<color>` 标签。
    // // 如果该路径没有颜色标签，则返回 `Ok(None)`。
    // //
    // // # 参数
    // // * `path` - 要读取颜色的保险库文件路径。
    // //
    // // # 返回
    // // 存在颜色标签时返回 `Ok(Some(color))`，未设置颜色时返回 `Ok(None)`。
    // //
    // // # 错误
    // // 当 `colorfulTag` 未启用时返回 `ColorfulTagError::FeatureDisabled`。
    // // 对查询失败返回其他 `ColorfulTagError` 变体。
    pub fn get_path_color(&self, path: &VaultPath) -> Result<Option<String>, ColorfulTagError> {
        self.ensure_colorful_tag_enabled()?;
        let existing_tags = match self.find_by_path(path)? {
            QueryPathResult::Found(entry) => entry.tags,
            QueryPathResult::NotFound => {
                return Err(TagError::FileNotFound(path.to_string()).into());
            }
        };

        // 1. 只读取路径级颜色标签；没有颜色时明确返回 None。
        Ok(existing_tags.into_iter().find_map(|tag| {
            tag.strip_prefix(COLOR_TAG_PREFIX)
                .map(|color| color.to_string())
        }))
    }

    fn ensure_colorful_tag_enabled(&self) -> Result<(), ColorfulTagError> {
        if self.is_colorful_tag_enabled()? {
            Ok(())
        } else {
            Err(ColorfulTagError::FeatureDisabled(COLORFUL_TAG_FEATURE))
        }
    }

    fn remove_existing_color_tags(&mut self, path: &VaultPath) -> Result<(), ColorfulTagError> {
        let existing_tags = match self.find_by_path(path)? {
            QueryPathResult::Found(entry) => entry.tags,
            QueryPathResult::NotFound => {
                return Err(TagError::FileNotFound(path.to_string()).into());
            }
        };

        // 1. 克隆现有颜色标签，避免在遍历查询结果时同时修改数据库。
        let color_tags: Vec<String> = existing_tags
            .into_iter()
            .filter(|tag| tag.starts_with(COLOR_TAG_PREFIX))
            .collect();

        // 2. 逐个删除旧颜色标签，使该路径最多只保留一个颜色。
        for tag in color_tags {
            self.remove_tag(path, &tag)?;
        }
        Ok(())
    }
}
