use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlResult, ToSqlOutput, Value, ValueRef};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 定义 VaultPath 操作中可能发生的错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    /// 尝试获取根目录 ("/") 的父目录。
    #[error("Cannot get the parent of the root directory")]
    ParentOfRoot,
    /// 尝试在文件路径上执行目录操作 (例如 join)。
    #[error("Cannot join a path segment to a file path")]
    JoinToFile,
}

/// 代表一个在vavavult内部的、绝对的、规范化的对象路径。
///
/// 严格区分 "文件" 和 "目录":
/// - 目录路径 **必须** 以 "/" 结尾 (e.g., "/a/b/").
/// - 文件路径 **必须不** 以 "/" 结尾 (e.g., "/a/b/c.txt").
/// - 根目录是特殊情况, 路径为 "/".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultPath {
    inner: String,
}

impl VaultPath {
    /// 从任何可以引用为 &str 的类型创建一个新的 VaultPath。
    ///
    /// 路径将被规范化:
    /// - 转换 '\' 为 '/'.
    /// - 解析 ".." 和 ".".
    /// - 确保路径以 "/" 开头.
    /// - 保留有意义的结尾 "/", 以区分文件和目录.
    pub fn new<S: AsRef<str>>(raw_path: S) -> Self {
        let normalized = Self::normalize(raw_path.as_ref());
        Self { inner: normalized }
    }

    /// 规范化路径的核心逻辑。
    fn normalize(raw_path: &str) -> String {
        let path_str = raw_path.replace('\\', "/");
        let had_trailing_slash = path_str.ends_with('/') && path_str.len() > 1;

        let mut components = Vec::new();
        for component in path_str.split('/') {
            match component {
                "" | "." => {} // 忽略空组件和 "."
                ".." => {
                    components.pop(); // 处理 ".."
                }
                // [修改] 检查并移除非法字符
                comp => {
                    // 定义非法字符集合
                    const ILLEGAL_CHARS: &[char] = &['\0', '<', '>', ':', '"', '|', '?', '*'];
                    // 使用 filter 移除非法字符
                    let sanitized_comp: String = comp.chars().filter(|c| !ILLEGAL_CHARS.contains(c)).collect();

                    // 只有在清理后的段不为空时才添加
                    if !sanitized_comp.is_empty() {
                        components.push(sanitized_comp);
                    }
                }
            }
        }

        if components.is_empty() {
            // 如果所有段都被移除（例如输入是 "///" 或 "/?*/"），则返回根目录
            return "/".to_string();
        }

        let mut result = format!("/{}", components.join("/"));

        // 如果原始路径有结尾斜杠, 并且结果不是根目录，则在规范化后保留它
        if had_trailing_slash && result != "/" {
            result.push('/');
        }

        result
    }

    /// 路径是否为根目录 ("/")。
    /// 这是两个主要判断依据之一。
    pub fn is_root(&self) -> bool {
        self.inner == "/"
    }

    /// 路径是否代表一个目录 (以 "/" 结尾)。
    /// 根目录 ("/") 也会返回 true。
    /// 这是两个主要判断依据之二。
    pub fn is_dir(&self) -> bool {
        self.inner.ends_with('/')
    }

    /// 路径是否代表一个文件 (不以 "/" 结尾)。
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// 返回父目录。
    ///
    /// - `/a/b/c.txt` (File) -> Ok(`/a/b/`)
    /// - `/a/b/c/` (Dir) -> Ok(`/a/b/`)
    /// - `/a.txt` (File) -> Ok(`/`)
    /// - `/a/` (Dir) -> Ok(`/`)
    /// - `/` (Root) -> Err(PathError::ParentOfRoot)
    pub fn parent(&self) -> Result<VaultPath, PathError> {
        if self.is_root() {
            return Err(PathError::ParentOfRoot);
        }

        let path_to_parse = if self.is_file() {
            &self.inner
        } else {
            // is_dir() 且 not is_root(), 所以它一定以 "/" 结尾
            &self.inner[..self.inner.len() - 1]
        };

        match path_to_parse.rfind('/') {
            Some(0) => Ok(VaultPath { inner: "/".to_string() }), // 父目录是根
            Some(idx) => Ok(VaultPath {
                // 父目录总是以 / 结尾
                inner: format!("{}/", &path_to_parse[..idx]),
            }),
            None => unreachable!(), // 理论上不应该发生, 因为所有路径都是绝对的
        }
    }

    /// 如果是文件，返回文件名；如果是目录，返回 None。
    ///
    /// - `/a/b/c.txt` -> `Some("c.txt")`
    /// - `/a/b/` -> `None`
    pub fn file_name(&self) -> Option<&str> {
        if self.is_file() {
            self.inner.rfind('/').map(|idx| &self.inner[idx + 1..])
        } else {
            None
        }
    }

    /// 如果是目录（非根），返回目录名；如果是文件或根，返回 None。
    ///
    /// - `/a/b/c/` -> `Some("c")`
    /// - `/a/b.txt` -> `None`
    /// - `/` -> `None`
    pub fn dir_name(&self) -> Option<&str> {
        if self.is_dir() && !self.is_root() {
            // 移除结尾的 '/', 找到前一个 '/'
            let trimmed = &self.inner[..self.inner.len() - 1];
            trimmed.rfind('/').map(|idx| &trimmed[idx + 1..])
        } else {
            None
        }
    }

    /// 将一个路径段连接到当前 **目录** 路径。
    ///
    /// - `segment` 是文件名: `/a/b/`.join("c.txt") -> Ok(`/a/b/c.txt`)
    /// - `segment` 是目录: `/a/b/`.join("c/") -> Ok(`/a/b/c/`)
    /// - 在文件上调用: `/a/b.txt`.join(...) -> Err(PathError::JoinToFile)
    ///
    /// `segment` 中的 `..` 或 `\` 会被自动规范化。
    pub fn join(&self, segment: &str) -> Result<VaultPath, PathError> {
        if self.is_file() {
            return Err(PathError::JoinToFile);
        }

        // self.inner 保证是 "/" 或以 "/" 结尾
        let new_path_str = format!("{}{}", self.inner, segment);
        Ok(VaultPath::new(new_path_str))
    }

    /// 以 &str 的形式返回规范化的路径字符串 (e.g., "/a/b/c.txt" 或 "/a/b/").
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// 将保险库路径转换为适合本地操作系统的相对路径 `PathBuf`。
    ///
    /// - `/a/b/c.txt` -> `a/b/c.txt`
    /// - `/a/b/` -> `a/b`
    pub fn as_os_path(&self) -> PathBuf {
        let mut relative_path = if self.inner.starts_with('/') {
            &self.inner[1..]
        } else {
            &self.inner
        };
        // 如果是目录，移除结尾的 /
        if relative_path.ends_with('/') && relative_path.len() > 1 {
            relative_path = &relative_path[..relative_path.len() - 1];
        }

        relative_path
            .split('/')
            .collect::<PathBuf>()
    }
}

/// 允许 `VaultPath::from("...")`
impl From<&str> for VaultPath {
    fn from(s: &str) -> Self {
        VaultPath::new(s)
    }
}

/// 允许 `VaultPath::from(Path::new("..."))`
impl From<&Path> for VaultPath {
    fn from(p: &Path) -> Self {
        VaultPath::new(p.to_string_lossy())
    }
}

/// 允许 `println!("{}", vault_path)`
impl Display for VaultPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

/// 存储到数据库时，编码为 TEXT
impl ToSql for VaultPath {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        // 存储规范化的字符串
        Ok(ToSqlOutput::Owned(Value::Text(self.as_str().to_string())))
    }
}

/// 从数据库 TEXT 读取
impl FromSql for VaultPath {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        value.as_str().map(|s| {
            // 从数据库读取时，我们信任它已经是规范化的
            // 但 VaultPath::new() 是幂等的，使用它更安全
            VaultPath::new(s)
        })
    }
}

// --- Serde (JSON, etc.) Support ---

/// 序列化为字符串
impl Serialize for VaultPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// 从字符串反序列化
impl<'de> Deserialize<'de> for VaultPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VaultPathVisitor;

        impl<'de> serde::de::Visitor<'de> for VaultPathVisitor {
            type Value = VaultPath;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a vault path string (e.g. /a/b.txt)")
            }

            // `VaultPath::new` 会处理规范化
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(VaultPath::new(value))
            }
        }

        deserializer.deserialize_str(VaultPathVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalization_and_type() {
        // (之前的测试用例保持不变)
        let p_file = VaultPath::new("a\\b\\c.txt");
        assert_eq!(p_file.as_str(), "/a/b/c.txt");
        assert!(p_file.is_file());

        let p_dir = VaultPath::new("a/b/");
        assert_eq!(p_dir.as_str(), "/a/b/");
        assert!(p_dir.is_dir());

        let p_file_like_dir = VaultPath::new("/a/b");
        assert_eq!(p_file_like_dir.as_str(), "/a/b");
        assert!(p_file_like_dir.is_file());

        let p_root = VaultPath::new("/");
        assert_eq!(p_root.as_str(), "/");
        assert!(p_root.is_dir());
        assert!(p_root.is_root());

        let p_complex_file = VaultPath::new("/a//b/../c/./d.txt");
        assert_eq!(p_complex_file.as_str(), "/a/c/d.txt");
        assert!(p_complex_file.is_file());

        let p_complex_dir = VaultPath::new("a\\b\\..\\c\\d\\");
        assert_eq!(p_complex_dir.as_str(), "/a/c/d/");
        assert!(p_complex_dir.is_dir());
    }

    #[test]
    fn test_illegal_char_removal() {
        assert_eq!(VaultPath::new("/a/b\0c.txt").as_str(), "/a/bc.txt");
        assert_eq!(VaultPath::new("/a<b/c>d/").as_str(), "/ab/cd/");
        assert_eq!(VaultPath::new("/a:b.txt").as_str(), "/ab.txt");
        assert_eq!(VaultPath::new("/a/\"bad name\"/").as_str(), "/a/bad name/");
        assert_eq!(VaultPath::new("/a|b").as_str(), "/ab");
        assert_eq!(VaultPath::new("/a/b?c/").as_str(), "/a/bc/");
        assert_eq!(VaultPath::new("/a*b.txt").as_str(), "/ab.txt");
        // 混合移除
        assert_eq!(VaultPath::new("/a/b*<c>?.d:e|f\"g\\h").as_str(), "/a/bc.defg/h");
        // 如果移除后段为空，则忽略该段
        assert_eq!(VaultPath::new("/a/<>/b").as_str(), "/a/b");
        assert_eq!(VaultPath::new("/a/*/").as_str(), "/a/"); // 移除*后段为空，被忽略
        assert_eq!(VaultPath::new("/*/a").as_str(), "/a");   // 同上
        assert_eq!(VaultPath::new("/*?/").as_str(), "/");    // 移除后都为空，只剩根
        assert_eq!(VaultPath::new("?").as_str(), "/");       // 移除后为空，只剩根
    }

    #[test]
    fn test_legal_chars() {
        // 测试一些常见的合法字符
        let p1 = VaultPath::new("/a b/c-d_e.txt");
        assert_eq!(p1.as_str(), "/a b/c-d_e.txt");
        let p2 = VaultPath::new("/文档/图片/");
        assert_eq!(p2.as_str(), "/文档/图片/");
    }

    #[test]
    fn test_parent() {
        assert_eq!(VaultPath::new("/a/b/c.txt").parent().unwrap().as_str(), "/a/b/");
        assert_eq!(VaultPath::new("/a/b/").parent().unwrap().as_str(), "/a/");
        assert_eq!(VaultPath::new("/a.txt").parent().unwrap().as_str(), "/");
        assert_eq!(VaultPath::new("/a/").parent().unwrap().as_str(), "/");
        assert_eq!(VaultPath::new("/").parent(), Err(PathError::ParentOfRoot));
    }

    #[test]
    fn test_file_name_and_dir_name() {
        let p_file = VaultPath::new("/a/b.txt");
        assert_eq!(p_file.file_name(), Some("b.txt"));
        assert_eq!(p_file.dir_name(), None);
        let p_dir = VaultPath::new("/a/b/");
        assert_eq!(p_dir.file_name(), None);
        assert_eq!(p_dir.dir_name(), Some("b"));
        let p_root = VaultPath::new("/");
        assert_eq!(p_root.file_name(), None);
        assert_eq!(p_root.dir_name(), None);
    }

    #[test]
    fn test_join() {
        let p_dir = VaultPath::new("/a/b/");
        assert_eq!(p_dir.join("c.txt").unwrap().as_str(), "/a/b/c.txt");
        assert_eq!(p_dir.join("c/").unwrap().as_str(), "/a/b/c/");
        let p_root = VaultPath::new("/");
        assert_eq!(p_root.join("c.txt").unwrap().as_str(), "/c.txt");
        assert_eq!(p_dir.join("c/d/../e.txt").unwrap().as_str(), "/a/b/c/e.txt");
        let p_file = VaultPath::new("/a/b.txt");
        assert_eq!(p_file.join("c.txt"), Err(PathError::JoinToFile));
    }

    #[test]
    fn test_join_with_illegal_segment_removal() {
        let p_dir = VaultPath::new("/a/b/");
        // join 会调用 VaultPath::new，应该移除非法字符
        assert_eq!(p_dir.join("illegal*char?.txt").unwrap().as_str(), "/a/b/illegalchar.txt");
        // 如果 segment 移除后为空，join 的结果应该不变
        assert_eq!(p_dir.join("?*/").unwrap().as_str(), "/a/b/");
        assert_eq!(p_dir.join("<>").unwrap().as_str(), "/a/b"); // 加入空文件名？VaultPath::new 会返回 "/" ? join 会 panic 还是？-> join 应该返回 Ok("/a/b/")
        // 确认一下：如果 join 一个只包含非法字符的段
        assert_eq!(p_dir.join("<>:\"?").unwrap().as_str(), "/a/b"); // join 一个空文件名，得到父目录的文件形式
        assert_eq!(p_dir.join("<>:\"?/").unwrap().as_str(), "/a/b/"); // join 一个空目录名，得到父目录
    }


    #[test]
    fn test_as_os_path() {
        let p_file = VaultPath::new("/a/b/c.txt");
        assert_eq!(p_file.as_os_path(), PathBuf::from("a").join("b").join("c.txt"));
        let p_dir = VaultPath::new("/a/b/");
        assert_eq!(p_dir.as_os_path(), PathBuf::from("a").join("b"));
        let p_root = VaultPath::new("/");
        assert_eq!(p_root.as_os_path(), PathBuf::from(""));
        // 测试包含非法字符的路径（它们应该已被移除）
        let p_illegal = VaultPath::new("/a/b*c/d?e.txt");
        assert_eq!(p_illegal.as_os_path(), PathBuf::from("a").join("bc").join("de.txt"));
    }
}