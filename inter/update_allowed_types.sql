-- 添加.bin到允许的文件类型
USE file_audit_system;

-- 添加.bin到允许的文件类型列表（如果不存在）
INSERT IGNORE INTO allowed_file_types (extension, description, is_active) VALUES ('.bin', '二进制文件', TRUE);

-- 验证添加成功
SELECT extension, description, is_active FROM allowed_file_types WHERE extension = '.bin';
