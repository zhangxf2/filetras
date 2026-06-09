# 内网导外网数据文件安全摆渡系统

一个基于 Python Flask 和 LDAP 认证的安全数据文件导出管理平台，通过审核流程确保只允许导出二进制文件，禁止代码文件外流。

## 功能特性

- 🔐 **LDAP 身份认证** - 集成企业 LDAP 服务器进行用户身份验证
- 📤 **文件上传与审核流程** - 完整的上传、审核、下载工作流
- 🔒 **严格的文件类型检查** - 基于扩展名、二进制内容的多重安全检查
- ❌ **禁止代码文件** - 禁止 .py, .js, .java, .c, .cpp 等代码文件
- ✅ **支持常用文件格式** - PDF、Office 文档、图片、视频、音频、压缩包
- 👤 **用户会话管理** - 登录状态保持、安全退出功能
- 📝 **操作审计记录** - 记录上传人、审核人、时间等信息
- 🎨 **美观的 Web 界面** - 现代化的 UI 设计

## 技术栈

- **后端**: Python 3.x, Flask 2.3.3
- **LDAP 认证**: ldap3 2.9.1
- **前端**: HTML5, CSS3, JavaScript
- **文件检测**: 二进制内容分析

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 LDAP

编辑 `config.ini` 文件，配置您的 LDAP 服务器信息：

```ini
[ldap]
server = ldap://127.0.0.1:389
username = CN=test,DC=com,DC=cn
password = 20250221@test
accountBase = OU=test,DC=test,DC=com,DC=cn
accountPattern = (&(sAMAccountName=${username}))
accountFullName = cn
accountEmailAddress = mail
readTimeout = 10s
```

### 3. 运行应用

```bash
python app.py
```

### 4. 访问系统

打开浏览器访问：`http://localhost:5001`

## 文件结构

```
inter/
├── app.py                 # 主应用程序
├── config.ini             # LDAP 配置文件
├── requirements.txt       # 依赖包列表
├── README.md             # 说明文档
├── uploads/              # 待审核文件存储目录
├── approved/             # 已审核文件存储目录
└── templates/            # HTML 模板
    ├── login.html        # 登录页面
    ├── index.html        # 首页（审核列表）
    └── upload.html       # 上传页面
```

## LDAP 配置说明

| 配置项 | 说明 | 示例 |
|--------|------|------|
| `server` | LDAP 服务器地址 | `ldap://127.0.0.1:389` |
| `username` | 绑定用户 DN | `CN=admin,DC=example,DC=com` |
| `password` | 绑定用户密码 | `your_password` |
| `accountBase` | 用户搜索基准 DN | `OU=Users,DC=example,DC=com` |
| `accountPattern` | 用户搜索过滤器 | `(&(sAMAccountName=${username}))` |
| `accountFullName` | 用户姓名字段 | `cn` |
| `accountEmailAddress` | 用户邮箱字段 | `mail` |

## 安全策略

### 禁止的文件类型

- **代码文件**: `.py, .pyc, .js, .jsx, .ts, .java, .class, .c, .cpp, .go, .php` 等
- **配置文件**: `.json, .yaml, .yml, .txt, .xml, .html` 等
- **脚本文件**: `.sh, .bash, .bat, .cmd, .ps1` 等
- **版本控制**: `.git, .gitignore` 等

### 允许的文件类型

- **文档**: `.pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx`
- **图片**: `.jpg, .jpeg, .png, .gif, .bmp, .tiff`
- **视频**: `.mp4, .avi, .mpeg, .mov, .mkv`
- **音频**: `.mp3, .wav, .flac, .aac`
- **压缩包**: `.zip, .rar, .7z, .tar, .gz`

### 检测机制

系统采用三重安全检测：

1. **扩展名检测** - 检查文件后缀是否在禁止/允许列表中
2. **MIME 类型检测** - 通过内容分析判断真实文件类型
3. **二进制检测** - 验证文件是否为真实的二进制格式

## 使用说明

### 登录系统

1. 访问系统首页
2. 输入 LDAP 用户名和密码
3. 点击「登录」按钮

### 上传文件

1. 点击「📤 上传文件」按钮
2. 填写导出原因说明
3. 选择要上传的文件
4. 点击「提交审核」

### 审核文件

1. 在首页「⏳ 待审核文件」列表中查看待审核文件
2. 点击「✅ 通过」批准文件下载
3. 点击「❌ 拒绝」拒绝文件申请

### 下载文件

1. 在「✅ 已审核文件」列表中查看已批准的文件
2. 点击「📥 下载」按钮下载文件

### 退出登录

1. 点击页面右上角的「退出」按钮
2. 系统安全退出并返回登录页面

## 生产环境部署建议

### 1. 修改密钥

在 `app.py` 中修改 `app.secret_key`：

```python
app.secret_key = 'your_secure_random_secret_key_here'
```

### 2. 使用数据库

当前版本使用内存存储，建议使用数据库：

```python
# 可以使用 SQLite, MySQL, PostgreSQL 等
import sqlite3
```

### 3. 配置 HTTPS

使用 SSL/TLS 加密传输：

```python
if __name__ == '__main__':
    app.run(
        debug=False,
        host='0.0.0.0',
        port=5001,
        ssl_context=('cert.pem', 'key.pem')
    )
```

### 4. 添加访问控制

- IP 白名单
- 用户角色权限管理
- 操作日志审计

## 故障排查

### LDAP 连接失败

- 检查 LDAP 服务器地址和端口
- 验证绑定用户 DN 和密码
- 检查网络连接和防火墙
- 查看控制台错误信息

### 文件上传失败

- 检查文件类型是否允许
- 验证文件是否为二进制格式
- 检查目录权限
- 查看服务器日志

### 认证失败

- 确认用户名和密码正确
- 检查用户是否存在于 LDAP 中
- 验证用户账户状态是否正常

## 开发说明

### 项目依赖

```txt
Flask==2.3.3
Werkzeug==2.3.7
ldap3==2.9.1
```

### 运行测试

```bash
python -m pytest tests/
```

### 代码规范

- 遵循 PEP 8 代码风格
- 使用类型注解
- 添加文档字符串

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

如有问题或建议，请联系系统管理员。
