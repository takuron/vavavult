use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use sha2::{Digest, Sha512};
use tempfile::tempdir;
use crate::common::metadata::MetadataEntry;
use crate::file::encrypt::EncryptionType;
use crate::vault;
use crate::vault::{AddFileError, OpenError, QueryError, QueryResult, Vault, VaultConfig};

#[test]
fn test_create_vault_success() {
    // 1. 创建一个临时目录用于测试
    let dir = tempdir().unwrap();
    let vault_path = dir.path();

    // 2. 调用我们的初始化函数
    let result = Vault::create_vault(vault_path, "my-test-vault",None);

    // 3. 断言操作成功
    assert!(result.is_ok());
    let vault = result.unwrap();
    let config = vault.config;
    assert_eq!(config.name, "my-test-vault");

    // 4. 验证文件是否已正确创建
    let master_json_path = vault_path.join("master.json");
    assert!(master_json_path.exists());
    assert!(master_json_path.is_file());

    let filelist_path = vault_path.join("master.db");
    assert!(filelist_path.exists());
    assert!(filelist_path.is_file());

    // 5. 验证文件内容
    let master_json_content = fs::read_to_string(master_json_path).unwrap();
    let parsed_config: VaultConfig = serde_json::from_str(&master_json_content).unwrap();
    assert_eq!(parsed_config.name, "my-test-vault");
    assert_eq!(parsed_config.encrypt_check.encrypted, "");

    // 临时目录会在 `dir` 离开作用域时自动被清理
}

#[test]
fn test_open_vault() {
    // 1. Setup: Create a vault first
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let original_vault_name = "my-persistent-vault";
    let vault = Vault::create_vault(vault_path, original_vault_name,None).unwrap();

    // Add a file to ensure state is persisted
    let source_file_path = vault_path.join("a.txt");
    File::create(&source_file_path).unwrap().write_all(b"a").unwrap();
    let original_hash = vault.add_file(&source_file_path, Some("a.txt")).unwrap();

    // The vault instance goes out of scope here, simulating closing the program
    drop(vault);

    // 2. Perform the open operation
    let opened_vault = Vault::open_vault(vault_path,None).unwrap();

    // 3. Verify the opened vault
    assert_eq!(opened_vault.config.name, original_vault_name);
    assert_eq!(opened_vault.root_path, vault_path);

    // Verify that the data is still there by querying it
    let result = opened_vault.find_by_hash(&original_hash).unwrap();
    assert!(matches!(result, QueryResult::Found(_)));
    if let QueryResult::Found(entry) = result {
        assert_eq!(entry.name, "/a.txt");
    }
}

#[test]
fn test_open_nonexistent_vault_error() {
    let dir = tempdir().unwrap();
    let non_existent_path = dir.path().join("nonexistent");
    let result = Vault::open_vault(&non_existent_path,None);
    assert!(matches!(result, Err(vault::OpenError::PathNotFound(_))));
}


#[test]
fn test_add_file_successfully() {
    // 1. 准备环境
    let dir = tempdir().unwrap(); // 创建一个临时目录
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    // 创建临时源文件
    let source_file_path1 = vault_path.join("my_test_file.txt");
    let mut source_file1 = File::create(&source_file_path1).unwrap();
    writeln!(source_file1, "Hello, Vault!").unwrap();

    let source_file_path2 = vault_path.join("my_test_file2.txt");
    let mut source_file2 = File::create(&source_file_path2).unwrap();
    writeln!(source_file2, "Hello, Vault New!").unwrap();

    // 2. 执行操作
    let result1 = vault.add_file(&source_file_path1, None);
    let result2 = vault.add_file(&source_file_path2, Some("/a/b/c/new_name.txt"));

    // 3. 断言结果
    assert!(result1.is_ok());
    assert!(result2.is_ok());
    let sha256sum1 = result1.unwrap();
    let sha256sum2 = result2.unwrap();

    // 4. 验证数据库
    let mut stmt = vault
        .database_connection
        .prepare("SELECT name FROM files WHERE sha256sum = ?1")
        .unwrap();
    let file_name1: String = stmt.query_row([&sha256sum1], |row| row.get(0)).unwrap();
    let file_name2: String = stmt.query_row([&sha256sum2], |row| row.get(0)).unwrap();

    assert_eq!(file_name1, "/my_test_file.txt");
    assert_eq!(file_name2, "/a/b/c/new_name.txt");

    // 验证文件是否已复制到目录
    let internal_path = vault.root_path.join(sha256sum1);
    assert!(internal_path.exists());
}

#[test]
fn test_add_duplicate_file_name() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    // 创建第一个文件
    let source_file_path1 = vault_path.join("file1.txt");
    File::create(&source_file_path1)
        .unwrap()
        .write_all(b"content1")
        .unwrap();
    vault
        .add_file(&source_file_path1, Some("shared_name.txt"))
        .unwrap();

    // 创建第二个内容不同的文件
    let source_file_path2 = vault_path.join("file2.txt");
    File::create(&source_file_path2)
        .unwrap()
        .write_all(b"content2")
        .unwrap();

    // 2. 执行操作 (尝试用同样的名字添加第二个文件)
    let result = vault.add_file(&source_file_path2, Some("shared_name.txt"));

    // 3. 断言结果
    assert!(matches!(result, Err(AddFileError::DuplicateFileName(_))));
}

#[test]
fn test_query_file_missing_from_disk_error() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    let source_file_path = vault_path.join("my_file.txt");
    File::create(&source_file_path).unwrap().write_all(b"i will be deleted").unwrap();
    let sha256sum = vault.add_file(&source_file_path, None).unwrap();

    // 2. 手动删除物理文件，制造不一致状态
    let internal_path = vault.root_path.join(&sha256sum);
    fs::remove_file(internal_path).unwrap();

    // 3. 执行查询并断言错误类型
    let result = vault.find_by_hash(&sha256sum);
    assert!(matches!(result, Err(QueryError::FileMissing(_))));
}

#[test]
fn test_list_and_path_query() {
    // 1. Setup
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    // Create a file structure
    let file_a_path = vault_path.join("a.txt");
    File::create(&file_a_path).unwrap().write_all(b"a").unwrap();
    vault.add_file(&file_a_path, Some("a.txt")).unwrap(); // -> /a.txt

    let file_b_path = vault_path.join("b.txt");
    File::create(&file_b_path).unwrap().write_all(b"b").unwrap();
    vault.add_file(&file_b_path, Some("b.txt")).unwrap(); // -> /b.txt

    let file_c_d_path = vault_path.join("d.txt");
    File::create(&file_c_d_path).unwrap().write_all(b"d").unwrap();
    vault.add_file(&file_c_d_path, Some("c/d.txt")).unwrap(); // -> /c/d.txt

    let file_c_e_path = vault_path.join("e.txt");
    File::create(&file_c_e_path).unwrap().write_all(b"e").unwrap();
    vault.add_file(&file_c_e_path, Some("c/e.txt")).unwrap(); // -> /c/e.txt

    let file_f_g_h_path = vault_path.join("h.txt");
    File::create(&file_f_g_h_path).unwrap().write_all(b"h").unwrap();
    vault.add_file(&file_f_g_h_path, Some("f/g/h.txt")).unwrap(); // -> /f/g/h.txt

    // 2. Test list_all
    let all_files = vault.list_all().unwrap();
    assert_eq!(all_files.len(), 5);

    // 3. Test list_by_path for root "/"
    let root_list = vault.list_by_path("/").unwrap();
    assert_eq!(root_list.files.len(), 2); // a.txt, b.txt
    assert_eq!(root_list.subdirectories.len(), 2); // c, f
    assert_eq!(root_list.files[0].name, "/a.txt");
    assert_eq!(root_list.files[1].name, "/b.txt");
    assert_eq!(root_list.subdirectories, vec!["c", "f"]);

    // 4. Test list_by_path for "/c/"
    let c_list = vault.list_by_path("/c/").unwrap();
    assert_eq!(c_list.files.len(), 2); // d.txt, e.txt
    assert_eq!(c_list.subdirectories.len(), 0);
    assert_eq!(c_list.files[0].name, "/c/d.txt");
    assert_eq!(c_list.files[1].name, "/c/e.txt");

    // 5. Test list_by_path for "/f/"
    let f_list = vault.list_by_path("/f/").unwrap();
    assert_eq!(f_list.files.len(), 0);
    assert_eq!(f_list.subdirectories.len(), 1); // g
    assert_eq!(f_list.subdirectories, vec!["g"]);

    // 6. Test list_by_path for an empty directory
    let g_list = vault.list_by_path("/f/g/").unwrap();
    assert_eq!(g_list.files.len(), 1); // h.txt
    assert_eq!(g_list.subdirectories.len(), 0);
    assert_eq!(g_list.files[0].name, "/f/g/h.txt");

    // 7. Test list_by_path for a non-existent path
    let non_existent_list = vault.list_by_path("/z/").unwrap();
    assert!(non_existent_list.files.is_empty());
    assert!(non_existent_list.subdirectories.is_empty());
}

#[test]
fn test_advanced_searches() {
    // 1. Setup
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    // Create files
    let report_path = vault_path.join("report.txt");
    File::create(&report_path).unwrap().write_all(b"report").unwrap();
    let report_hash = vault.add_file(&report_path, Some("2024_report_final.txt")).unwrap();

    let image_path = vault_path.join("image.jpg");
    File::create(&image_path).unwrap().write_all(b"image").unwrap();
    let image_hash = vault.add_file(&image_path, Some("vacation_photo.jpg")).unwrap();

    let draft_path = vault_path.join("draft.md");
    File::create(&draft_path).unwrap().write_all(b"draft").unwrap();
    let draft_hash = vault.add_file(&draft_path, Some("draft_report.md")).unwrap();

    // Add tags
    vault.add_tags(&report_hash, &["work", "finance", "final"]).unwrap();
    vault.add_tags(&image_hash, &["personal", "vacation"]).unwrap();
    vault.add_tags(&draft_hash, &["work", "draft"]).unwrap();

    // 2. Test find_by_tag
    let work_files = vault.find_by_tag("work").unwrap();
    assert_eq!(work_files.len(), 2); // report_final.txt, draft_report.md

    let vacation_files = vault.find_by_tag("vacation").unwrap();
    assert_eq!(vacation_files.len(), 1);
    assert_eq!(vacation_files[0].sha256sum, image_hash);

    let no_files = vault.find_by_tag("nonexistent").unwrap();
    assert!(no_files.is_empty());

    // 3. Test find_by_name_fuzzy
    let report_files = vault.find_by_name_fuzzy("report").unwrap();
    assert_eq!(report_files.len(), 2); // 2024_report_final.txt, draft_report.md

    let vacation_files_fuzzy = vault.find_by_name_fuzzy("vacation").unwrap();
    assert_eq!(vacation_files_fuzzy.len(), 1);
    assert_eq!(vacation_files_fuzzy[0].sha256sum, image_hash);

    // 4. Test find_by_name_and_tag_fuzzy
    let final_work_reports = vault.find_by_name_and_tag_fuzzy("report", "final").unwrap();
    assert_eq!(final_work_reports.len(), 1);
    assert_eq!(final_work_reports[0].sha256sum, report_hash);

    let draft_work_reports = vault.find_by_name_and_tag_fuzzy("report", "work").unwrap();
    assert_eq!(draft_work_reports.len(), 2);

    let personal_reports = vault.find_by_name_and_tag_fuzzy("report", "personal").unwrap();
    assert!(personal_reports.is_empty());
}

#[test]
fn test_rename_file() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    let source_file_path = vault_path.join("rename_me.txt");
    File::create(&source_file_path).unwrap().write_all(b"rename content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("old_name.txt")).unwrap();

    // 2. 执行重命名操作
    let new_name = "new/path/to/file.txt";
    let rename_result = vault.rename_file(&sha256sum, new_name);
    assert!(rename_result.is_ok());

    // 3. 验证结果
    // 用旧名字查，应该找不到了
    let old_name_result = vault.find_by_name( "/old_name.txt").unwrap();
    assert!(matches!(old_name_result, QueryResult::NotFound));

    // 用新名字查，应该能找到
    let new_name_result = vault.find_by_name( "/new/path/to/file.txt").unwrap();
    if let QueryResult::Found(entry) = new_name_result {
        assert_eq!(entry.sha256sum, sha256sum);
    } else {
        panic!("File should be found by its new name");
    }

    // 尝试重命名为一个已存在的名字，应该会失败
    let other_file_path = vault_path.join("other.txt");
    File::create(&other_file_path).unwrap().write_all(b"other content").unwrap();
    vault.add_file(&other_file_path, Some("existing_name.txt")).unwrap();

    let failed_rename_result = vault.rename_file(&sha256sum, "existing_name.txt");
    assert!(matches!(failed_rename_result, Err(vault::UpdateError::DuplicateFileName(_))));
}

#[test]
fn test_tag_management() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    let source_file_path = vault_path.join("tag_me.txt");
    File::create(&source_file_path).unwrap().write_all(b"tag content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("tagged_file.txt")).unwrap();

    // 2. 添加单个标签
    vault.add_tag(&sha256sum, "rust").unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert_eq!(entry.tags, vec!["rust"]);
    } else {
        panic!("File not found after adding a tag");
    }

    // 3. 批量添加标签 (包含一个已存在的)
    vault.add_tags( &sha256sum, &["project", "important", "rust"]).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        // 验证标签已排序且无重复
        assert_eq!(entry.tags, vec!["important", "project", "rust"]);
    } else {
        panic!("File not found after adding multiple tags");
    }

    // 4. 删除一个标签
    vault.remove_tag(&sha256sum, "project").unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash( &sha256sum).unwrap() {
        assert_eq!(entry.tags, vec!["important", "rust"]);
    } else {
        panic!("File not found after removing a tag");
    }

    // 5. 删除所有标签
    vault.clear_tags(&sha256sum).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert!(entry.tags.is_empty());
    } else {
        panic!("File not found after clearing tags");
    }
}

#[test]
fn test_metadata_management() {
    // 1. Setup
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    let source_file_path = vault_path.join("metadata_file.txt");
    File::create(&source_file_path).unwrap().write_all(b"metadata content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("metadata_file.txt")).unwrap();

    // 2. Set a new metadata entry
    vault.set_metadata(&sha256sum, MetadataEntry{
        key:"author".to_string(),
        value:"John Doe".to_string()
    }).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert_eq!(entry.metadata.len(), 1);
        assert_eq!(entry.metadata[0].key, "author");
        assert_eq!(entry.metadata[0].value, "John Doe");
    } else {
        panic!("File not found after setting metadata");
    }

    // 3. Update an existing metadata entry
    vault.set_metadata(&sha256sum, MetadataEntry{
        key:"author".to_string(),
        value:"Jane Smith".to_string()
    }).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert_eq!(entry.metadata.len(), 1);
        assert_eq!(entry.metadata[0].value, "Jane Smith");
    } else {
        panic!("File not found after updating metadata");
    }

    // 4. Set a second metadata entry
    vault.set_metadata(&sha256sum, MetadataEntry{
        key:"status".to_string(),
        value:"draft".to_string()
    }).unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert_eq!(entry.metadata.len(), 2);
    } else {
        panic!("File not found after adding second metadata entry");
    }

    // 5. Remove a metadata entry
    vault.remove_metadata(&sha256sum, "author").unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert_eq!(entry.metadata.len(), 1);
        assert_eq!(entry.metadata[0].key, "status");
    } else {
        panic!("File not found after removing metadata");
    }

    // 6. Remove the last metadata entry
    vault.remove_metadata(&sha256sum, "status").unwrap();
    if let QueryResult::Found(entry) = vault.find_by_hash(&sha256sum).unwrap() {
        assert!(entry.metadata.is_empty());
    } else {
        panic!("File not found after clearing metadata");
    }
}

#[test]
fn test_extract_file() {
    // 1. Setup
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    let source_file_path = vault_path.join("extract_me.txt");
    let original_content = "content to be extracted";
    File::create(&source_file_path)
        .unwrap()
        .write_all(original_content.as_bytes())
        .unwrap();
    let sha256sum = vault
        .add_file(&source_file_path, Some("extract_me.txt"))
        .unwrap();

    // 2. Perform extraction
    let destination_path = dir.path().join("output/extracted_file.txt");
    vault.extract_file(&sha256sum, &destination_path).unwrap();

    // 3. Verify the extracted file
    assert!(destination_path.exists());
    let extracted_content =fs::read_to_string(destination_path).unwrap();
    assert_eq!(original_content, extracted_content);
}

#[test]
fn test_remove_file() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault = Vault::create_vault(vault_path, "test_vault",None).unwrap();

    let source_file_path = vault_path.join("delete_me.txt");
    File::create(&source_file_path).unwrap().write_all(b"delete content").unwrap();
    let sha256sum = vault.add_file(&source_file_path, Some("to_be_deleted.txt")).unwrap();

    // 确认文件已添加
    let internal_path = vault.root_path.join(&sha256sum);
    assert!(internal_path.exists());
    assert!(matches!(vault.find_by_hash( &sha256sum).unwrap(), QueryResult::Found(_)));

    // 2. 执行删除操作
    let remove_result = vault.remove_file(&sha256sum);
    assert!(remove_result.is_ok());

    // 3. 验证结果
    // 物理文件应被删除
    assert!(!internal_path.exists());
    // 数据库记录应被删除
    let query_result = vault.find_by_hash(&sha256sum).unwrap();
    assert!(matches!(query_result, QueryResult::NotFound));
}

/// 测试加密库的创建和访问控制
#[test]
fn test_encrypted_vault_creation_and_access() {
    // 1. 准备环境
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let vault_name = "access-control-test";
    let password = "a_strong_password_123!";

    // 2. 成功创建加密库
    let vault = Vault::create_vault(vault_path, vault_name, Some(password)).unwrap();

    // 验证配置是否正确
    assert_eq!(vault.config.encrypt_type, EncryptionType::Aes256Gcm);
    assert!(vault.config.encrypt_check.verify(password));

    // 添加一个文件以验证数据库的可写性
    let source_file_path = vault_path.join("test.txt");
    File::create(&source_file_path).unwrap().write_all(b"data").unwrap();
    let hash = vault.add_file(&source_file_path, None).unwrap();
    assert!(matches!(vault.find_by_hash(&hash).unwrap(), QueryResult::Found(_)));

    // 销毁 vault 实例，模拟关闭
    drop(vault);

    // 3. 测试访问控制
    // a. 用错误密码打开，应该失败
    let err = Vault::open_vault(vault_path, Some("wrong_password")).unwrap_err();
    assert!(matches!(err, OpenError::InvalidPassword));

    // b. 不提供密码打开，应该失败
    let err = Vault::open_vault(vault_path, None).unwrap_err();
    assert!(matches!(err, OpenError::PasswordRequired));

    // c. 用正确密码打开，应该成功
    let opened_vault = Vault::open_vault(vault_path, Some(password)).unwrap();
    assert_eq!(opened_vault.config.name, vault_name);

    // 验证之前添加的数据依然可以被读取
    let result = opened_vault.find_by_hash(&hash).unwrap();
    assert!(matches!(result, QueryResult::Found(_)));
}

/// 测试加密文件的完整添加（加密）和提取（解密）周期
#[test]
fn test_add_and_extract_encrypted_file() {
    // 1. 准备环境：创建一个加密的 vault
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let password = "my-vault-password";
    let vault = Vault::create_vault(vault_path, "encrypted_extract_test", Some(password)).unwrap();

    // 2. 准备源文件
    let source_file_path = vault_path.join("secret_data.txt");
    let original_content = "This is a secret message that should be encrypted and then decrypted successfully.";
    File::create(&source_file_path)
        .unwrap()
        .write_all(original_content.as_bytes())
        .unwrap();

    // 3. 将文件添加到加密 vault 中
    let sha256sum = vault
        .add_file(&source_file_path, Some("secrets/my_secret.txt"))
        .unwrap();

    // 4. 准备提取文件的目标路径
    let destination_path = dir.path().join("extracted_data/retrieved_secret.txt");

    // 5. 执行提取操作
    let extract_result = vault.extract_file(&sha256sum, &destination_path);
    assert!(extract_result.is_ok());

    // 6. 验证结果
    // a. 确认目标文件已创建
    assert!(destination_path.exists());
    // b. 读取提取出的文件内容
    let extracted_content = fs::read_to_string(destination_path).unwrap();
    // c. 确认提取出的内容与原始内容完全一致
    assert_eq!(original_content, extracted_content);
}

/// 最终的、全面的集成测试，模拟用户的完整使用流程
#[test]
fn test_full_vault_integration() {
    // 1. 创建临时目录和加密 Vault
    let dir = tempdir().unwrap();
    let vault_path = dir.path();
    let password = "full-integration-test-password-!@#";
    let vault = Vault::create_vault(vault_path, "integration-vault", Some(password)).unwrap();
    assert_eq!(vault.config.name, "integration-vault");
    assert_eq!(vault.config.encrypt_type, EncryptionType::Aes256Gcm);

    // 2. 创建一个大型随机文件并计算其原始 SHA512 哈希
    let file1_path = vault_path.join("large_document.bin");
    let mut source_file = File::create(&file1_path).unwrap();
    let mut original_hasher = Sha512::new();
    let mut buffer = [0u8; 8192];
    for _ in 0..(1024 * 1024 / 8192) { // 创建一个 1MB 的文件
        openssl::rand::rand_bytes(&mut buffer).unwrap();
        source_file.write_all(&buffer).unwrap();
        original_hasher.update(&buffer);
    }
    let original_hash_sha512 = hex::encode(original_hasher.finalize());


    // 3. 添加文件到 Vault
    let hash1 = vault.add_file(&file1_path, Some("docs/large_document.bin")).unwrap();

    // 4. 提取 (解密) 文件
    let extract_path = dir.path().join("extracted.bin");
    vault.extract_file(&hash1, &extract_path).unwrap();

    // 5. 计算提取后文件的 SHA512 哈希
    let mut extracted_file = File::open(&extract_path).unwrap();
    let mut extracted_hasher = Sha512::new();
    loop {
        let bytes_read = extracted_file.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        extracted_hasher.update(&buffer[..bytes_read]);
    }
    let extracted_hash_sha512 = hex::encode(extracted_hasher.finalize());

    // 6. [核心校验] 断言原始哈希和提取后的哈希完全一致
    assert_eq!(original_hash_sha512, extracted_hash_sha512, "SHA512 hash of extracted file does not match the original file's hash.");


    // 7. 继续进行其他功能的健全性检查
    let file2_path = vault_path.join("image.jpg");
    fs::write(&file2_path, b"fake image data").unwrap();
    let hash2 = vault.add_file(&file2_path, Some("media/image.jpg")).unwrap();

    assert!(matches!(vault.find_by_hash(&hash1).unwrap(), QueryResult::Found(_)));
    assert_eq!(vault.list_all().unwrap().len(), 2);

    vault.add_tag(&hash1, "important").unwrap();
    let entry1 = match vault.find_by_hash(&hash1).unwrap() {
        QueryResult::Found(e) => e,
        _ => panic!("File should be found"),
    };
    assert_eq!(entry1.tags, vec!["important"]);

    vault.remove_file(&hash1).unwrap();
    assert!(matches!(vault.find_by_hash(&hash1).unwrap(), QueryResult::NotFound));
    assert_eq!(vault.list_all().unwrap().len(), 1);

    // 8. 关闭并重新打开 Vault 以测试持久性
    drop(vault);
    let reopened_vault = Vault::open_vault(vault_path, Some(password)).unwrap();

    // 检查剩下的文件依然存在
    assert!(matches!(reopened_vault.find_by_hash(&hash2).unwrap(), QueryResult::Found(_)));
}