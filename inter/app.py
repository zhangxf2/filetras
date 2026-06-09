import os
import configparser
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session, jsonify
from werkzeug.utils import secure_filename
from ldap3 import Server, Connection, ALL, SUBTREE
import pymysql
from pymysql.cursors import DictCursor
from dbutils.pooled_db import PooledDB
import threading
import time

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_change_in_production'

# 大文件上传配置
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 * 1024  # 8GB
app.config['UPLOAD_CHUNK_SIZE'] = 4 * 1024 * 1024  # 4MB每块

# 上传进度跟踪（线程安全）
upload_progress = {}
upload_progress_lock = threading.Lock()

# 缓存配置
cache = {
    'allowed_extensions': None,
    'forbidden_extensions': None,
    'allowed_extensions_time': None,
    'forbidden_extensions_time': None,
    'cache_ttl': 300  # 5分钟缓存
}
cache_lock = threading.Lock()

# 数据库连接池
db_pool = None

# 加载配置文件
def load_config():
    config = configparser.ConfigParser()
    config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
    config.read(config_file, encoding='utf-8')
    return config

def init_db_pool():
    config = load_config()
    db_config = config['database']
    global db_pool
    db_pool = PooledDB(
        creator=pymysql,
        maxconnections=20,  # 最大连接数
        mincached=5,       # 最小空闲连接
        maxcached=10,      # 最大空闲连接
        blocking=True,
        host=db_config['host'],
        port=int(db_config['port']),
        user=db_config['username'],
        password=db_config['password'],
        database=db_config['database'],
        charset=db_config['charset'],
        cursorclass=DictCursor
    )

def get_db_connection():
    global db_pool
    if db_pool is None:
        init_db_pool()
    return db_pool.connection()

# 从数据库获取允许的文件类型（带缓存）
def get_allowed_extensions():
    global cache
    now = time.time()
    
    # 检查缓存是否有效
    with cache_lock:
        if (cache['allowed_extensions'] is not None and 
            cache['allowed_extensions_time'] is not None and 
            now - cache['allowed_extensions_time'] < cache['cache_ttl']):
            return cache['allowed_extensions']
    
    # 从数据库获取
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT extension FROM allowed_file_types WHERE is_active = TRUE")
            result = {row['extension'].lower() for row in cursor.fetchall()}
            
            # 更新缓存
            with cache_lock:
                cache['allowed_extensions'] = result
                cache['allowed_extensions_time'] = now
            
            return result
    finally:
        conn.close()

# 从数据库获取禁止的文件类型（带缓存）
def get_forbidden_extensions():
    global cache
    now = time.time()
    
    # 检查缓存是否有效
    with cache_lock:
        if (cache['forbidden_extensions'] is not None and 
            cache['forbidden_extensions_time'] is not None and 
            now - cache['forbidden_extensions_time'] < cache['cache_ttl']):
            return cache['forbidden_extensions']
    
    # 从数据库获取
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT extension FROM forbidden_file_types WHERE is_active = TRUE")
            result = {row['extension'].lower() for row in cursor.fetchall()}
            
            # 更新缓存
            with cache_lock:
                cache['forbidden_extensions'] = result
                cache['forbidden_extensions_time'] = now
            
            return result
    finally:
        conn.close()

# 清除文件类型缓存
def clear_file_type_cache():
    with cache_lock:
        cache['allowed_extensions'] = None
        cache['forbidden_extensions'] = None
        cache['allowed_extensions_time'] = None
        cache['forbidden_extensions_time'] = None

# 获取用户角色（从数据库实时读取）
def get_user_roles(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT r.name 
                FROM roles r 
                INNER JOIN user_roles ur ON r.id = ur.role_id 
                WHERE ur.user_id = %s
            ''', (user_id,))
            return [row['name'] for row in cursor.fetchall()]
    finally:
        conn.close()

# 检查用户是否有指定角色（从数据库实时读取，不依赖Session缓存）
def has_role(role_name):
    if 'user' not in session:
        return False
    # 每次都从数据库读取最新角色，确保角色变更即时生效
    roles = get_user_roles(session['user']['id'])
    return role_name in roles

# 登录装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 角色权限装饰器
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_role(role_name):
                flash('权限不足！', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 记录操作日志
def log_audit(action, resource_type=None, resource_id=None, details=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user_id = session.get('user', {}).get('id') if 'user' in session else None
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            cursor.execute('''
                INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (user_id, action, resource_type, resource_id, details, ip_address, user_agent))
        conn.commit()
    finally:
        conn.close()

# 生成密文下载令牌
def generate_download_token():
    """生成安全的下载令牌"""
    return secrets.token_urlsafe(32)

# 邮件配置（从 config.ini 读取）
def get_email_config():
    config = load_config()
    email_config = config['email'] if 'email' in config else {}
    return {
        'smtp_server': email_config.get('smtp_server', 'localhost'),
        'smtp_port': int(email_config.get('smtp_port', 25)),
        'smtp_username': email_config.get('smtp_username', ''),
        'smtp_password': email_config.get('smtp_password', ''),
        'sender_email': email_config.get('sender_email', 'noreply@example.com'),
        'use_tls': email_config.get('use_tls', 'true').lower() == 'true'
    }

# 发送邮件通知
def send_download_email(to_email, filename, download_url):
    """发送包含下载链接的邮件"""
    email_config = get_email_config()
    
    subject = f"文件审核通过 - {filename}"
    body = f"""
    <html>
        <body>
            <h2>文件审核通过通知</h2>
            <p>您好，您上传的文件 <strong>{filename}</strong> 已审核通过。</p>
            <p>请点击以下链接下载文件：</p>
            <p><a href="{download_url}" style="display:inline-block;padding:10px 20px;background:#667eea;color:white;text-decoration:none;border-radius:5px;">下载文件</a></p>
            <p>或复制链接到浏览器：</p>
            <p style="background:#f5f5f5;padding:10px;border-radius:5px;font-family:monospace;">{download_url}</p>
            <p><small>此链接24小时内有效，且只能使用一次。</small></p>
            <hr>
            <p style="color:#666;font-size:12px;">此邮件由系统自动发送，请勿回复。</p>
        </body>
    </html>
    """
    
    try:
        msg = MIMEMultipart()
        msg['From'] = email_config['sender_email']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            # 尝试开启TLS，如果失败就跳过
            if email_config['use_tls']:
                try:
                    server.starttls()
                except Exception as e:
                    print(f"TLS不可用，继续不加密连接: {e}")
            
            # 如果有用户名密码，尝试登录
            if email_config['smtp_username'] and email_config['smtp_password']:
                try:
                    server.login(email_config['smtp_username'], email_config['smtp_password'])
                except Exception as e:
                    print(f"SMTP登录失败，尝试不登录发送: {e}")
            
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"发送邮件失败: {e}")
        return False

# 分块上传API
@app.route('/upload/chunk', methods=['POST'])
@login_required
def upload_chunk():
    """处理分块上传"""
    try:
        chunk = request.files['chunk']
        chunk_index = int(request.form.get('chunkIndex', 0))
        total_chunks = int(request.form.get('totalChunks', 1))
        upload_id = request.form.get('uploadId', '')
        filename = request.form.get('filename', '')
        
        # 创建临时目录
        temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{upload_id}')
        os.makedirs(temp_dir, exist_ok=True)
        
        # 保存当前块
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index}')
        chunk.save(chunk_path)
        
        # 更新进度（线程安全）
        with upload_progress_lock:
            if upload_id not in upload_progress:
                upload_progress[upload_id] = {
                    'total': total_chunks,
                    'uploaded': 0,
                    'filename': filename,
                    'status': 'uploading'
                }
            
            upload_progress[upload_id]['uploaded'] = chunk_index + 1
        
        # 检查是否上传完成
        if chunk_index + 1 == total_chunks:
            with upload_progress_lock:
                upload_progress[upload_id]['status'] = 'merging'
            
            # 合并所有块
            final_filename = secure_filename(filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            saved_filename = f"{timestamp}_{final_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            
            with open(file_path, 'wb') as final_file:
                for i in range(total_chunks):
                    chunk_path = os.path.join(temp_dir, f'chunk_{i}')
                    if os.path.exists(chunk_path):
                        with open(chunk_path, 'rb') as chunk_file:
                            final_file.write(chunk_file.read())
                        os.remove(chunk_path)
            
            # 删除临时目录
            try:
                os.rmdir(temp_dir)
            except:
                pass
            
            with upload_progress_lock:
                upload_progress[upload_id]['status'] = 'completed'
                upload_progress[upload_id]['file_path'] = file_path
                upload_progress[upload_id]['saved_filename'] = saved_filename
                upload_progress[upload_id]['original_filename'] = filename
        
        # 获取状态（线程安全）
        with upload_progress_lock:
            status = upload_progress[upload_id]['status']
        
        return jsonify({
            'success': True,
            'chunkIndex': chunk_index,
            'status': status
        })
    
    except Exception as e:
        print(f"分块上传错误: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# 获取上传进度
@app.route('/upload/progress/<upload_id>')
@login_required
def get_upload_progress(upload_id):
    """获取上传进度"""
    with upload_progress_lock:
        if upload_id in upload_progress:
            return jsonify(upload_progress[upload_id])
    return jsonify({
        'total': 0,
        'uploaded': 0,
        'status': 'not_found'
    })

# 清理旧的上传进度
def clean_old_uploads():
    """清理超过24小时的上传记录"""
    cutoff = datetime.now() - timedelta(hours=24)
    to_delete = []
    
    with upload_progress_lock:
        for upload_id, info in list(upload_progress.items()):
            if info.get('completed_at') and info['completed_at'] < cutoff:
                to_delete.append(upload_id)
        
        for upload_id in to_delete:
            del upload_progress[upload_id]

# 初始化数据库
def init_database():
    config = load_config()
    db_config = config['database']
    
    # 创建数据库（如果不存在）
    conn = pymysql.connect(
        host=db_config['host'],
        port=int(db_config['port']),
        user=db_config['username'],
        password=db_config['password'],
        charset='utf8mb4'
    )
    
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_config['database']}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()
    
    # 连接到数据库并创建表
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 创建用户表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    full_name VARCHAR(200) NOT NULL,
                    email VARCHAR(200),
                    ldap_dn TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT NULL,
                    INDEX idx_username (username),
                    INDEX idx_is_active (is_active)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 创建角色表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS roles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(50) UNIQUE NOT NULL,
                    description VARCHAR(200),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 创建用户角色关联表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_roles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    role_id INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                    UNIQUE KEY uk_user_role (user_id, role_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 创建文件表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    original_filename VARCHAR(255) NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size BIGINT,
                    file_type VARCHAR(100),
                    upload_reason TEXT,
                    uploader_id INT NOT NULL,
                    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                    reviewer_id INT,
                    review_comment TEXT,
                    reviewed_at DATETIME DEFAULT NULL,
                    download_token VARCHAR(255),
                    download_token_expires DATETIME,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT NULL,
                    FOREIGN KEY (uploader_id) REFERENCES users(id),
                    FOREIGN KEY (reviewer_id) REFERENCES users(id),
                    INDEX idx_status (status),
                    INDEX idx_uploader (uploader_id),
                    INDEX idx_download_token (download_token),
                    INDEX idx_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 创建操作日志表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    action VARCHAR(50) NOT NULL,
                    resource_type VARCHAR(50),
                    resource_id INT,
                    details TEXT,
                    ip_address VARCHAR(50),
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    INDEX idx_action (action),
                    INDEX idx_user (user_id),
                    INDEX idx_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 创建允许的文件类型表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS allowed_file_types (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    extension VARCHAR(50) UNIQUE NOT NULL,
                    description VARCHAR(200),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT NULL,
                    INDEX idx_extension (extension),
                    INDEX idx_is_active (is_active)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 创建禁止的文件类型表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS forbidden_file_types (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    extension VARCHAR(50) UNIQUE NOT NULL,
                    description VARCHAR(200),
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT NULL,
                    INDEX idx_extension (extension),
                    INDEX idx_is_active (is_active)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # 初始化角色数据
            cursor.execute("SELECT COUNT(*) as count FROM roles")
            if cursor.fetchone()['count'] == 0:
                cursor.execute("INSERT INTO roles (name, description) VALUES ('admin', '系统管理员'), ('reviewer', '审核人员'), ('user', '普通用户')")
            
            # 初始化允许的文件类型
            cursor.execute("SELECT COUNT(*) as count FROM allowed_file_types")
            if cursor.fetchone()['count'] == 0:
                cursor.execute('''
                    INSERT INTO allowed_file_types (extension, description) VALUES 
                    ('.pdf', 'PDF文档'),
                    ('.doc', 'Word文档'),
                    ('.docx', 'Word文档'),
                    ('.xls', 'Excel表格'),
                    ('.xlsx', 'Excel表格'),
                    ('.ppt', 'PowerPoint演示'),
                    ('.pptx', 'PowerPoint演示'),
                    ('.jpg', 'JPG图片'),
                    ('.jpeg', 'JPEG图片'),
                    ('.png', 'PNG图片'),
                    ('.gif', 'GIF图片'),
                    ('.bmp', 'BMP图片'),
                    ('.zip', 'ZIP压缩包'),
                    ('.rar', 'RAR压缩包'),
                    ('.7z', '7Z压缩包'),
                    ('.txt', '文本文件'),
                    ('.csv', 'CSV文件'),
                    ('.dwg', 'AutoCAD图纸'),
                    ('.dxf', 'AutoCAD图纸'),
                    ('.step', 'STEP 3D文件'),
                    ('.stp', 'STP 3D文件'),
                    ('.igs', 'IGS 3D文件'),
                    ('.iges', 'IGES 3D文件'),
                    ('.bin', '二进制文件')
                ''')
            
            # 初始化禁止的文件类型
            cursor.execute("SELECT COUNT(*) as count FROM forbidden_file_types")
            if cursor.fetchone()['count'] == 0:
                cursor.execute('''
                    INSERT INTO forbidden_file_types (extension, description) VALUES 
                    ('.py', 'Python源代码'),
                    ('.java', 'Java源代码'),
                    ('.c', 'C源代码'),
                    ('.cpp', 'C++源代码'),
                    ('.h', 'C/C++头文件'),
                    ('.js', 'JavaScript源代码'),
                    ('.ts', 'TypeScript源代码'),
                    ('.html', 'HTML文件'),
                    ('.htm', 'HTML文件'),
                    ('.css', 'CSS样式文件'),
                    ('.php', 'PHP源代码'),
                    ('.rb', 'Ruby源代码'),
                    ('.go', 'Go源代码'),
                    ('.rs', 'Rust源代码'),
                    ('.swift', 'Swift源代码'),
                    ('.kt', 'Kotlin源代码'),
                    ('.scala', 'Scala源代码'),
                    ('.sh', 'Shell脚本'),
                    ('.bat', 'Windows批处理'),
                    ('.ps1', 'PowerShell脚本'),
                    ('.sql', 'SQL脚本'),
                    ('.xml', 'XML文件'),
                    ('.json', 'JSON文件'),
                    ('.yaml', 'YAML文件'),
                    ('.yml', 'YAML文件'),
                    ('.ini', '配置文件'),
                    ('.conf', '配置文件'),
                    ('.config', '配置文件'),
                    ('.env', '环境配置文件')
                ''')
        conn.commit()
    finally:
        conn.close()

# 创建上传目录
UPLOAD_FOLDER = 'uploads'
APPROVED_FOLDER = 'approved'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(APPROVED_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['APPROVED_FOLDER'] = APPROVED_FOLDER

# 文件签名（Magic Bytes）映射
FILE_SIGNATURES = {
    # PDF
    b'%PDF': ['.pdf'],
    # Office文档
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': ['.doc', '.xls', '.ppt'],
    b'PK\x03\x04': ['.docx', '.xlsx', '.pptx', '.zip', '.jar', '.war', '.ear'],
    # 图片
    b'\xff\xd8\xff': ['.jpg', '.jpeg'],
    b'\x89PNG\r\n\x1a\n': ['.png'],
    b'GIF8': ['.gif'],
    b'BM': ['.bmp'],
    b'II*\x00': ['.tif', '.tiff'],
    b'MM\x00*': ['.tif', '.tiff'],
    # 视频
    b'\x00\x00\x00\x18ftyp': ['.mp4'],
    b'RIFF': ['.avi', '.wav'],
    b'\x1aE\xdf\xa3': ['.mkv', '.webm'],
    # 音频
    b'ID3': ['.mp3'],
    b'OggS': ['.ogg', '.oga'],
    b'\xff\xfb': ['.mp3'],
    # 压缩包
    b'\x1f\x8b\x08': ['.gz', '.tgz'],
    b'Rar!': ['.rar'],
    b'7z\xbc\xaf\x27\x1c': ['.7z'],
    # AutoCAD
    b'AutoCAD': ['.dwg', '.dxf'],
    b'AC\x10': ['.dwg'],
    # 3D文件
    b'\x00\x00\x01\x00': ['.ico'],
}

# 常见代码文件特征
CODE_PATTERNS = [
    # Python
    b'import ',
    b'def ',
    b'class ',
    b'from ',
    b'if __name__',
    # JavaScript/TypeScript
    b'function',
    b'const ',
    b'let ',
    b'var ',
    b'export ',
    b'import ',
    # Java
    b'public class',
    b'private ',
    b'protected ',
    b'static ',
    b'void ',
    # C/C++
    b'#include',
    b'#define',
    b'int main',
    # PHP
    b'<?php',
    b'<?=',
    # Shell
    b'#!/bin',
    b'#!/usr/bin',
    # HTML
    b'<html',
    b'<!DOCTYPE',
    b'<script',
    # SQL
    b'SELECT ',
    b'INSERT ',
    b'UPDATE ',
    b'DELETE ',
    b'CREATE ',
]

# 检查禁止文件类型
def is_forbidden_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    forbidden_exts = get_forbidden_extensions()
    return ext in forbidden_exts

# 检查是否允许的扩展名
def is_allowed_extension(filename):
    ext = os.path.splitext(filename)[1].lower()
    allowed_exts = get_allowed_extensions()
    return ext in allowed_exts

# 检查文件签名是否匹配
def matches_file_signature(file_path, ext):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)  # 读取文件头32字节
        
        for signature, extensions in FILE_SIGNATURES.items():
            if header.startswith(signature) and ext in extensions:
                return True
        
        # 对于不常见的文件类型，我们跳过签名验证
        return True
    except:
        return False

# 检查是否为已知合法文件类型（快速检查）
def is_known_valid_file_type(file_path, ext):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)
        
        for signature, extensions in FILE_SIGNATURES.items():
            if header.startswith(signature) and ext in extensions:
                return True
        
        return False
    except:
        return False

# 检查是否包含代码内容
def has_code_content(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read(10240)  # 读取前10KB进行检查
        
        for pattern in CODE_PATTERNS:
            if pattern in content:
                return True
        
        return False
    except:
        return False

# 检查是否为二进制文件
def is_binary_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(4096)
        
        # 检查是否有不可打印字符
        textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        if chunk:
            non_text_bytes = len(chunk.translate(None, textchars))
            non_text_ratio = non_text_bytes / len(chunk)
        
        # 3. 如果有超过10%的非文本字符，认为是二进制（降低阈值）
        if non_text_ratio > 0.1:
            return True
        
        return False
    except:
        return False

# 扫描压缩包是否包含代码文件
def scan_archive_for_code(file_path, ext):
    """扫描压缩包是否包含代码文件"""
    allowed_exts = get_allowed_extensions()
    forbidden_exts = get_forbidden_extensions()
    
    if ext in ['.zip']:
        try:
            import zipfile
            with zipfile.ZipFile(file_path, 'r') as zf:
                for name in zf.namelist():
                    # 跳过目录
                    if name.endswith('/'):
                        continue
                    
                    # 检查文件扩展名
                    file_ext = os.path.splitext(name)[1].lower()
                    
                    # 如果文件类型在允许列表中，直接跳过
                    if file_ext in allowed_exts:
                        continue
                    
                    if file_ext in forbidden_exts:
                        return f'压缩包内包含禁止的文件类型: {name}'
                    
                    # 检查多级扩展名（如 file.txt.py）
                    parts = name.lower().split('.')
                    for part in parts[1:]:
                        if '.' + part in forbidden_exts and '.' + part not in allowed_exts:
                            return f'压缩包内包含可疑文件: {name}'
                    
                    # 对所有不在允许列表的文件都进行内容检测
                    try:
                        with zf.open(name) as f:
                            # 读取更多内容进行检测
                            content = f.read(131072)  # 读取前128KB
                            
                            # 更全面的代码特征检测
                            code_signatures = [
                                b'<?php',
                                b'<?=',
                                b'#!/usr/bin',
                                b'#!/bin',
                                b'#!/env',
                                b'import ',
                                b'from ',
                                b'require ',
                                b'include ',
                                b'function',
                                b'class ',
                                b'public ',
                                b'private ',
                                b'protected ',
                                b'static ',
                                b'def ',
                                b'fn ',
                                b'SELECT ',
                                b'INSERT ',
                                b'UPDATE ',
                                b'DELETE ',
                                b'CREATE ',
                                b'ALTER ',
                                b'DROP ',
                                b'<script',
                                b'</script>',
                                b'<?xml',
                                b'<!DOCTYPE',
                                b'<html',
                                b'const ',
                                b'let ',
                                b'var ',
                                b'if (',
                                b'if(',
                                b'else ',
                                b'for (',
                                b'for(',
                                b'while (',
                                b'while(',
                                b' = ',
                                b' === ',
                                b' !== ',
                                b' => ',
                                b'->{',
                                b'(){',
                                b'function(',
                                b'def ',
                            ]
                            
                            for sig in code_signatures:
                                if sig in content:
                                    return f'压缩包内文件包含代码特征: {name}'
                    except:
                        pass
        except Exception as e:
            print(f"扫描压缩包出错: {e}")
    
    elif ext in ['.rar', '.7z', '.tar', '.gz']:
        # 其他压缩格式，建议只使用ZIP
        return f'为了安全起见，请使用ZIP格式压缩包，其他压缩格式不支持内容检查'
    
    return None

# 完整的文件内容验证
def validate_file_content(file_path, filename):
    """完整的文件内容验证"""
    ext = os.path.splitext(filename)[1].lower()
    
    errors = []
    
    # 对于压缩文件，必须检查内容，即使是已知的有效文件类型
    if ext in ['.zip']:
        # 检查压缩包内容
        archive_error = scan_archive_for_code(file_path, ext)
        if archive_error:
            errors.append(archive_error)
        # 检查文件签名匹配
        if not matches_file_signature(file_path, ext):
            errors.append('文件内容与扩展名不匹配')
        return errors
    
    # 对于其他文件类型，先检查是否是已知的合法文件类型
    if is_known_valid_file_type(file_path, ext):
        return []
    
    # 1. 检查是否是二进制文件
    if not is_binary_file(file_path):
        errors.append('文件看起来不是有效的二进制文件')
    
    # 2. 检查是否包含代码内容
    if has_code_content(file_path):
        errors.append('检测到代码文件特征，禁止上传')
    
    # 3. 检查文件签名匹配（防止冒充）
    if not matches_file_signature(file_path, ext):
        errors.append('文件内容与扩展名不匹配')
    
    # 4. 检查其他压缩包内容
    archive_error = scan_archive_for_code(file_path, ext)
    if archive_error:
        errors.append(archive_error)
    
    return errors

# 合并完成后继续处理
@app.route('/upload/complete/<upload_id>', methods=['POST'])
@login_required
def complete_upload(upload_id):
    """完成上传后的处理"""
    # 线程安全读取
    with upload_progress_lock:
        if upload_id not in upload_progress or upload_progress[upload_id]['status'] != 'completed':
            return jsonify({'success': False, 'error': '上传未完成'})
        progress = upload_progress[upload_id]
    
    reason = request.form.get('reason', '')
    filename = progress['original_filename']
    file_path = progress['file_path']
    saved_filename = progress['saved_filename']
    
    try:
        # 检查禁止文件类型
        if is_forbidden_file(filename):
            os.remove(file_path)
            with upload_progress_lock:
                del upload_progress[upload_id]
            return jsonify({'success': False, 'error': '禁止上传代码文件！'})
        
        # 检查允许的扩展名
        if not is_allowed_extension(filename):
            os.remove(file_path)
            with upload_progress_lock:
                del upload_progress[upload_id]
            return jsonify({'success': False, 'error': '文件类型不允许！请上传PDF、Office文档、图片、视频、音频或压缩包。'})
        
        # 执行文件内容验证
        validation_errors = validate_file_content(file_path, filename)
        if validation_errors:
            os.remove(file_path)
            with upload_progress_lock:
                del upload_progress[upload_id]
            return jsonify({
                'success': False,
                'error': '文件验证失败：' + '；'.join(validation_errors)
            })
        
        # 获取文件信息
        file_size = os.path.getsize(file_path)
        file_type = os.path.splitext(filename)[1].lower()
        
        # 保存到数据库
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('''
                    INSERT INTO files (filename, original_filename, file_path, file_size, file_type, upload_reason, uploader_id, status) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
                ''', (saved_filename, filename, file_path, file_size, file_type, reason, session['user']['id']))
                file_id = cursor.lastrowid
            conn.commit()
            log_audit('upload', 'file', file_id, f'上传文件: {filename}')
        finally:
            conn.close()
        
        # 清理进度数据（线程安全）
        with upload_progress_lock:
            if upload_id in upload_progress:
                upload_progress[upload_id]['completed_at'] = datetime.now()
            del upload_progress[upload_id]
        
        # 定期清理旧上传
        if datetime.now().second % 10 == 0:  # 每10个请求清理一次
            clean_old_uploads()
        
        return jsonify({'success': True, 'redirect': url_for('index')})
    
    except Exception as e:
        print(f"完成上传错误: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# LDAP搜索用户（不需要密码）
def ldap_search_user(username):
    config = load_config()
    ldap_config = config['ldap']
    
    if not ldap_config.get('enabled', 'false').lower() == 'true':
        return None
    
    try:
        server = Server(ldap_config['server'], get_info=ALL)
        conn = Connection(server, user=f"{ldap_config['bind_dn']}", password=ldap_config['bind_password'], auto_bind=True)
        
        # 搜索用户
        search_base = ldap_config['base_dn']
        search_filter = f"({ldap_config['username_attribute']}={username})"
        
        conn.search(search_base, search_filter, attributes=[
            ldap_config['username_attribute'],
            ldap_config.get('name_attribute', 'cn'),
            ldap_config.get('email_attribute', 'mail')
        ])
        
        if len(conn.entries) == 0:
            return None
        
        # 获取用户信息（不验证密码）
        user = {
            'username': str(conn.entries[0][ldap_config['username_attribute']]),
            'full_name': str(conn.entries[0][ldap_config.get('name_attribute', 'cn')]) if ldap_config.get('name_attribute') in conn.entries[0] else username,
            'email': str(conn.entries[0][ldap_config.get('email_attribute', 'mail')]) if ldap_config.get('email_attribute') in conn.entries[0] else '',
            'dn': str(conn.entries[0].entry_dn)
        }
        
        conn.unbind()
        return user
    except Exception as e:
        print(f"LDAP搜索错误: {e}")
        return None

# LDAP认证
def ldap_auth(username, password):
    config = load_config()
    ldap_config = config['ldap']
    
    if not ldap_config.get('enabled', 'false').lower() == 'true':
        return None
    
    try:
        server = Server(ldap_config['server'], get_info=ALL)
        conn = Connection(server, user=f"{ldap_config['bind_dn']}", password=ldap_config['bind_password'], auto_bind=True)
        
        # 搜索用户
        search_base = ldap_config['base_dn']
        search_filter = f"({ldap_config['username_attribute']}={username})"
        
        conn.search(search_base, search_filter, attributes=[
            ldap_config['username_attribute'],
            ldap_config.get('name_attribute', 'cn'),
            ldap_config.get('email_attribute', 'mail')
        ])
        
        if len(conn.entries) == 0:
            return None
        
        user_dn = conn.entries[0].entry_dn
        
        # 验证用户密码
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
        except:
            return None
        
        # 获取用户信息
        user = {
            'username': str(conn.entries[0][ldap_config['username_attribute']]),
            'full_name': str(conn.entries[0][ldap_config.get('name_attribute', 'cn')]) if ldap_config.get('name_attribute') in conn.entries[0] else username,
            'email': str(conn.entries[0][ldap_config.get('email_attribute', 'mail')]) if ldap_config.get('email_attribute') in conn.entries[0] else '',
            'dn': user_dn
        }
        
        conn.unbind()
        return user
    except Exception as e:
        print(f"LDAP认证错误: {e}")
        return None

# 同步用户到数据库
def sync_user(ldap_user):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 检查用户是否存在
            cursor.execute('SELECT * FROM users WHERE username = %s', (ldap_user['username'],))
            existing_user = cursor.fetchone()
            
            if existing_user:
                # 更新用户信息
                cursor.execute('''
                    UPDATE users 
                    SET full_name = %s, email = %s, ldap_dn = %s, updated_at = %s
                    WHERE id = %s
                ''', (ldap_user['full_name'], ldap_user['email'], ldap_user['dn'], datetime.now(), existing_user['id']))
                user_id = existing_user['id']
            else:
                # 创建新用户
                cursor.execute('''
                    INSERT INTO users (username, full_name, email, ldap_dn)
                    VALUES (%s, %s, %s, %s)
                ''', (ldap_user['username'], ldap_user['full_name'], ldap_user['email'], ldap_user['dn']))
                user_id = cursor.lastrowid
                
                # 分配默认角色
                cursor.execute("SELECT id FROM roles WHERE name = 'user'")
                user_role = cursor.fetchone()
                if user_role:
                    cursor.execute('INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)', (user_id, user_role['id']))
            
            conn.commit()
            
            # 返回用户信息
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            return cursor.fetchone()
    finally:
        conn.close()

# 获取用户角色（从数据库实时读取）
def get_user_roles_from_db(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT r.name 
                FROM roles r 
                INNER JOIN user_roles ur ON r.id = ur.role_id 
                WHERE ur.user_id = %s
            ''', (user_id,))
            return [row['name'] for row in cursor.fetchall()]
    finally:
        conn.close()

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('请输入用户名和密码！', 'danger')
            return render_template('login.html')
        
        # 先尝试简单的本地管理员登录（用于测试）
        if username == 'admin' and password == 'admin123':
            # 检查admin用户是否存在
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT * FROM users WHERE username = %s', ('admin',))
                    admin_user = cursor.fetchone()
                    
                    if not admin_user:
                        # 创建admin用户
                        cursor.execute('''
                            INSERT INTO users (username, full_name, email)
                            VALUES (%s, %s, %s)
                        ''', ('admin', '系统管理员', 'admin@localhost'))
                        admin_id = cursor.lastrowid
                        
                        # 分配admin角色
                        cursor.execute("SELECT id FROM roles WHERE name = 'admin'")
                        admin_role = cursor.fetchone()
                        if admin_role:
                            cursor.execute('INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)', (admin_id, admin_role['id']))
                        
                        # 分配user角色
                        cursor.execute("SELECT id FROM roles WHERE name = 'user'")
                        user_role = cursor.fetchone()
                        if user_role:
                            cursor.execute('INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)', (admin_id, user_role['id']))
                        
                        conn.commit()
                        cursor.execute('SELECT * FROM users WHERE id = %s', (admin_id,))
                        admin_user = cursor.fetchone()
                    
                    session['user'] = {
                        'id': admin_user['id'],
                        'username': admin_user['username'],
                        'full_name': admin_user['full_name'],
                        'email': admin_user['email']
                    }
                    session['user_roles'] = get_user_roles(admin_user['id'])
                    log_audit('login', 'user', admin_user['id'], '用户登录成功（本地管理员）')
                    flash(f'欢迎, {admin_user["full_name"]}!', 'success')
                    return redirect(url_for('index'))
            finally:
                conn.close()
        
        # 尝试LDAP认证
        ldap_user = ldap_auth(username, password)
        if ldap_user:
            user = sync_user(ldap_user)
            session['user'] = {
                'id': user['id'],
                'username': user['username'],
                'full_name': user['full_name'],
                'email': user['email']
            }
            session['user_roles'] = get_user_roles(user['id'])
            log_audit('login', 'user', user['id'], '用户登录成功')
            flash(f'欢迎, {user["full_name"]}!', 'success')
            return redirect(url_for('index'))
        else:
            log_audit('login_failed', None, None, f'用户名: {username}')
            flash('用户名或密码错误！', 'danger')
    
    return render_template('login.html')

# 退出登录
@app.route('/logout')
def logout():
    if 'user' in session:
        log_audit('logout', 'user', session['user']['id'], '用户退出登录')
    session.pop('user', None)
    session.pop('user_roles', None)
    flash('已安全退出！', 'info')
    return redirect(url_for('login'))

# 首页
@app.route('/')
@login_required
def index():
    page_pending = request.args.get('page_pending', 1, type=int)
    page_approved = request.args.get('page_approved', 1, type=int)
    per_page = 10  # 每页显示10条
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取用户的实时角色
            current_roles = get_user_roles(session['user']['id'])
            
            # ========== 待审核文件分页 ==========
            # 获取总数
            if has_role('admin') or has_role('reviewer'):
                cursor.execute('''
                    SELECT COUNT(*) as total 
                    FROM files f 
                    WHERE f.status = 'pending'
                ''')
            else:
                cursor.execute('''
                    SELECT COUNT(*) as total 
                    FROM files f 
                    WHERE f.status = 'pending' AND f.uploader_id = %s
                ''', (session['user']['id'],))
            total_pending = cursor.fetchone()['total']
            total_pages_pending = (total_pending + per_page - 1) // per_page
            
            # 获取当前页数据
            offset_pending = (page_pending - 1) * per_page
            if has_role('admin') or has_role('reviewer'):
                cursor.execute('''
                    SELECT f.*, u1.full_name as uploader_name 
                    FROM files f 
                    INNER JOIN users u1 ON f.uploader_id = u1.id 
                    WHERE f.status = 'pending' 
                    ORDER BY f.created_at DESC
                    LIMIT %s OFFSET %s
                ''', (per_page, offset_pending))
            else:
                cursor.execute('''
                    SELECT f.*, u1.full_name as uploader_name 
                    FROM files f 
                    INNER JOIN users u1 ON f.uploader_id = u1.id 
                    WHERE f.status = 'pending' AND f.uploader_id = %s 
                    ORDER BY f.created_at DESC
                    LIMIT %s OFFSET %s
                ''', (session['user']['id'], per_page, offset_pending))
            pending_files = cursor.fetchall()
            
            # ========== 已审核文件分页 ==========
            # 获取总数
            if has_role('admin') or has_role('reviewer'):
                cursor.execute('''
                    SELECT COUNT(*) as total 
                    FROM files f 
                    WHERE f.status IN ('approved', 'rejected')
                ''')
            else:
                cursor.execute('''
                    SELECT COUNT(*) as total 
                    FROM files f 
                    WHERE f.status IN ('approved', 'rejected') AND f.uploader_id = %s
                ''', (session['user']['id'],))
            total_approved = cursor.fetchone()['total']
            total_pages_approved = (total_approved + per_page - 1) // per_page
            
            # 获取当前页数据
            offset_approved = (page_approved - 1) * per_page
            if has_role('admin') or has_role('reviewer'):
                cursor.execute('''
                    SELECT f.*, u1.full_name as uploader_name, u2.full_name as reviewer_name 
                    FROM files f 
                    INNER JOIN users u1 ON f.uploader_id = u1.id 
                    LEFT JOIN users u2 ON f.reviewer_id = u2.id 
                    WHERE f.status IN ('approved', 'rejected') 
                    ORDER BY f.created_at DESC
                    LIMIT %s OFFSET %s
                ''', (per_page, offset_approved))
            else:
                cursor.execute('''
                    SELECT f.*, u1.full_name as uploader_name, u2.full_name as reviewer_name 
                    FROM files f 
                    INNER JOIN users u1 ON f.uploader_id = u1.id 
                    LEFT JOIN users u2 ON f.reviewer_id = u2.id 
                    WHERE f.status IN ('approved', 'rejected') AND f.uploader_id = %s 
                    ORDER BY f.created_at DESC
                    LIMIT %s OFFSET %s
                ''', (session['user']['id'], per_page, offset_approved))
            approved_files = cursor.fetchall()
            
            # 为已通过的文件准备下载链接（如果没有令牌则生成）
            for file in approved_files:
                if file['status'] == 'approved':
                    if not file['download_token'] or (file['download_token_expires'] and datetime.now() > file['download_token_expires']):
                        # 生成新令牌
                        new_token = generate_download_token()
                        new_expires = datetime.now() + timedelta(hours=24)
                        cursor.execute('''
                            UPDATE files 
                            SET download_token = %s, download_token_expires = %s, updated_at = %s 
                            WHERE id = %s
                        ''', (new_token, new_expires, datetime.now(), file['id']))
                        conn.commit()
                        file['download_token'] = new_token
                        file['download_token_expires'] = new_expires
            
            return render_template('index.html', 
                                 pending_files=pending_files, 
                                 approved_files=approved_files,
                                 current_roles=current_roles,
                                 user=session['user'],
                                 page_pending=page_pending,
                                 total_pages_pending=total_pages_pending,
                                 total_pending=total_pending,
                                 page_approved=page_approved,
                                 total_pages_approved=total_pages_approved,
                                 total_approved=total_approved)
    finally:
        conn.close()

# 上传文件
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('没有选择文件', 'danger')
            return redirect(request.url)
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash('请填写导出原因', 'danger')
            return redirect(request.url)
        
        if file:
            original_filename = file.filename
            filename = secure_filename(file.filename)
            
            if is_forbidden_file(filename):
                log_audit('upload_forbidden', 'file', None, f'禁止上传文件: {filename}')
                flash('禁止上传代码文件！', 'danger')
                return redirect(request.url)
            
            if not is_allowed_extension(filename):
                log_audit('upload_invalid_type', 'file', None, f'文件类型不允许: {filename}')
                flash('文件类型不允许！请上传PDF、Office文档、图片、视频、音频或压缩包。', 'danger')
                return redirect(request.url)
            
            # 保存文件
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            saved_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            file.save(file_path)
            
            # 执行完整的文件内容验证
            validation_errors = validate_file_content(file_path, filename)
            if validation_errors:
                os.remove(file_path)
                error_msg = '；'.join(validation_errors)
                log_audit('upload_invalid_content', 'file', None, f'文件内容验证失败: {filename} - {error_msg}')
                flash(f'文件验证失败：{error_msg}', 'danger')
                return redirect(request.url)
            
            # 获取文件信息
            file_size = os.path.getsize(file_path)
            file_type = os.path.splitext(filename)[1].lower()
            
            # 保存到数据库
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO files (filename, original_filename, file_path, file_size, file_type, upload_reason, uploader_id, status) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
                    ''', (saved_filename, original_filename, file_path, file_size, file_type, reason, session['user']['id']))
                    file_id = cursor.lastrowid
                conn.commit()
                log_audit('upload', 'file', file_id, f'上传文件: {original_filename}')
                flash('文件上传成功，等待审核', 'success')
            finally:
                conn.close()
            
            return redirect(url_for('index'))
    
    # 获取当前用户的角色
    current_roles = get_user_roles(session['user']['id'])
    return render_template('upload.html', user=session['user'], current_roles=current_roles)

# 审核文件 - 通过
@app.route('/approve/<int:file_id>')
@login_required
@role_required('reviewer')
def approve_file(file_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT f.*, u.email as uploader_email 
                FROM files f 
                LEFT JOIN users u ON f.uploader_id = u.id 
                WHERE f.id = %s
            ''', (file_id,))
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('文件不存在', 'danger')
                return redirect(url_for('index'))
            
            if file_info['status'] != 'pending':
                flash('该文件已审核过', 'warning')
                return redirect(url_for('index'))
            
            # 生成下载令牌
            download_token = generate_download_token()
            token_expires = datetime.now() + timedelta(hours=24)  # 24小时有效
            
            # 更新文件状态和令牌信息
            cursor.execute('''
                UPDATE files 
                SET status = 'approved', reviewer_id = %s, reviewed_at = %s, 
                    download_token = %s, download_token_expires = %s, updated_at = %s 
                WHERE id = %s
            ''', (session['user']['id'], datetime.now(), download_token, token_expires, datetime.now(), file_id))
            
            # 移动文件到 approved 目录
            src_path = file_info['file_path']
            dst_filename = file_info['filename']
            dst_path = os.path.join(app.config['APPROVED_FOLDER'], dst_filename)
            
            if os.path.exists(src_path):
                os.rename(src_path, dst_path)
                cursor.execute("UPDATE files SET file_path = %s, updated_at = %s WHERE id = %s", (dst_path, datetime.now(), file_id))
            
            conn.commit()
            log_audit('approve', 'file', file_id, f'审核通过文件: {file_info["original_filename"]}')
            
            # 发送邮件通知（如果有邮箱）
            if file_info.get('uploader_email'):
                download_url = url_for('download_file', token=download_token, _external=True)
                if send_download_email(file_info['uploader_email'], file_info['original_filename'], download_url):
                    log_audit('email_sent', 'file', file_id, f'发送邮件通知到: {file_info["uploader_email"]}')
                    flash('文件审核通过，邮件通知已发送！', 'success')
                else:
                    flash('文件审核通过！', 'success')
            else:
                flash('文件审核通过！', 'success')
            
            return redirect(url_for('index'))
    finally:
        conn.close()

# 审核文件 - 拒绝
@app.route('/reject/<int:file_id>')
@login_required
@role_required('reviewer')
def reject_file(file_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM files WHERE id = %s', (file_id,))
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('文件不存在', 'danger')
                return redirect(url_for('index'))
            
            if file_info['status'] != 'pending':
                flash('该文件已审核过', 'warning')
                return redirect(url_for('index'))
            
            # 更新文件状态
            cursor.execute('''
                UPDATE files 
                SET status = 'rejected', reviewer_id = %s, reviewed_at = %s, review_comment = '', updated_at = %s 
                WHERE id = %s
            ''', (session['user']['id'], datetime.now(), datetime.now(), file_id))
            
            # 删除文件
            if os.path.exists(file_info['file_path']):
                os.remove(file_info['file_path'])
            
            conn.commit()
            log_audit('reject', 'file', file_id, f'审核拒绝文件: {file_info["original_filename"]}')
            flash('文件已拒绝', 'info')
            
            return redirect(url_for('index'))
    finally:
        conn.close()

# 下载文件（使用令牌）
@app.route('/download/<token>')
def download_file(token):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT f.*, u.email as uploader_email 
                FROM files f 
                LEFT JOIN users u ON f.uploader_id = u.id 
                WHERE f.download_token = %s
            ''', (token,))
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('无效的下载链接', 'danger')
                return render_template('error.html', message='无效的下载链接')
            
            if file_info['status'] != 'approved':
                flash('该文件未审核通过', 'danger')
                return render_template('error.html', message='该文件未审核通过')
            
            if file_info['download_token_expires'] and datetime.now() > file_info['download_token_expires']:
                flash('下载链接已过期', 'danger')
                return render_template('error.html', message='下载链接已过期')
            
            log_audit('download', 'file', file_info['id'], f'下载文件: {file_info["original_filename"]}')
            
            # 返回文件
            return send_file(file_info['file_path'], as_attachment=True, download_name=file_info['original_filename'])
    finally:
        conn.close()

# 用户管理页面
@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取当前用户的角色
            current_roles = get_user_roles(session['user']['id'])
            
            cursor.execute('''
                SELECT u.*, 
                       GROUP_CONCAT(r.name) as roles 
                FROM users u 
                LEFT JOIN user_roles ur ON u.id = ur.user_id 
                LEFT JOIN roles r ON ur.role_id = r.id 
                GROUP BY u.id 
                ORDER BY u.created_at DESC
            ''')
            users = cursor.fetchall()
            
            cursor.execute('SELECT * FROM roles ORDER BY name')
            roles = cursor.fetchall()
            
            return render_template('admin/users.html', users=users, roles=roles, user=session['user'], current_roles=current_roles)
    finally:
        conn.close()

# 添加LDAP用户
@app.route('/admin/users/add', methods=['POST'])
@login_required
@role_required('admin')
def add_ldap_user():
    username = request.form.get('username', '').strip()
    
    if not username:
        flash('请输入用户名', 'danger')
        return redirect(url_for('admin_users'))
    
    # 检查用户是否已存在
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            if cursor.fetchone():
                flash('该用户已存在', 'warning')
                return redirect(url_for('admin_users'))
            
            # 从LDAP搜索用户
            ldap_user = ldap_search_user(username)
            if not ldap_user:
                flash('在LDAP中未找到该用户', 'danger')
                return redirect(url_for('admin_users'))
            
            # 添加用户到数据库
            user = sync_user(ldap_user)
            log_audit('add_user', 'user', user['id'], f'手动添加用户: {user["full_name"]}')
            flash(f'用户 {user["full_name"]} 已添加', 'success')
            
            return redirect(url_for('admin_users'))
    finally:
        conn.close()

# 更新用户角色
@app.route('/admin/user/<int:user_id>/roles', methods=['POST'])
@login_required
@role_required('admin')
def update_user_roles(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 先删除用户现有角色
            cursor.execute('DELETE FROM user_roles WHERE user_id = %s', (user_id,))
            
            # 添加新角色
            selected_roles = request.form.getlist('roles')
            for role_name in selected_roles:
                cursor.execute('SELECT id FROM roles WHERE name = %s', (role_name,))
                role = cursor.fetchone()
                if role:
                    cursor.execute('INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)', (user_id, role['id']))
            
            conn.commit()
            log_audit('update_roles', 'user', user_id, f'更新用户角色: {", ".join(selected_roles)}')
            flash('用户角色已更新', 'success')
            
            return redirect(url_for('admin_users'))
    finally:
        conn.close()

# 操作日志页面
@app.route('/admin/logs')
@login_required
@role_required('admin')
def admin_logs():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取当前用户的角色
            current_roles = get_user_roles(session['user']['id'])
            
            cursor.execute('''
                SELECT a.*, u.full_name as user_name 
                FROM audit_logs a 
                LEFT JOIN users u ON a.user_id = u.id 
                ORDER BY a.created_at DESC 
                LIMIT 500
            ''')
            logs = cursor.fetchall()
            
            return render_template('admin/logs.html', logs=logs, user=session['user'], current_roles=current_roles)
    finally:
        conn.close()

# 文件类型管理页面
@app.route('/admin/file-types')
@login_required
@role_required('admin')
def admin_file_types():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取当前用户的角色
            current_roles = get_user_roles(session['user']['id'])
            
            cursor.execute('SELECT * FROM allowed_file_types ORDER BY extension')
            allowed_types = cursor.fetchall()
            
            cursor.execute('SELECT * FROM forbidden_file_types ORDER BY extension')
            forbidden_types = cursor.fetchall()
            
            return render_template('admin/file_types.html', allowed_types=allowed_types, forbidden_types=forbidden_types, user=session['user'], current_roles=current_roles)
    finally:
        conn.close()

# 切换允许/禁止文件类型状态
@app.route('/admin/file-types/<category>/<int:type_id>/toggle', methods=['POST'])
@login_required
@role_required('admin')
def toggle_file_type(category, type_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            table = 'allowed_file_types' if category == 'allowed' else 'forbidden_file_types'
            cursor.execute(f'UPDATE {table} SET is_active = NOT is_active WHERE id = %s', (type_id,))
            conn.commit()
        # 清除缓存
        clear_file_type_cache()
        flash('文件类型状态已更新', 'success')
        return redirect(url_for('admin_file_types'))
    finally:
        conn.close()

# 删除文件类型
@app.route('/admin/file-types/<category>/<int:type_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_file_type(category, type_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            table = 'allowed_file_types' if category == 'allowed' else 'forbidden_file_types'
            cursor.execute(f'DELETE FROM {table} WHERE id = %s', (type_id,))
            conn.commit()
        # 清除缓存
        clear_file_type_cache()
        flash('文件类型已删除', 'success')
        return redirect(url_for('admin_file_types'))
    finally:
        conn.close()

# 添加文件类型
@app.route('/admin/file-types/<category>/add', methods=['POST'])
@login_required
@role_required('admin')
def add_file_type(category):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            table = 'allowed_file_types' if category == 'allowed' else 'forbidden_file_types'
            extension = request.form.get('extension', '').lower().strip()
            description = request.form.get('description', '').strip()
            
            if not extension.startswith('.'):
                extension = '.' + extension
            
            try:
                cursor.execute(f'INSERT INTO {table} (extension, description) VALUES (%s, %s)', (extension, description))
                conn.commit()
                # 清除缓存
                clear_file_type_cache()
                flash('文件类型已添加', 'success')
            except pymysql.err.IntegrityError:
                flash('该文件类型已存在', 'danger')
        
        return redirect(url_for('admin_file_types'))
    finally:
        conn.close()

# 编辑用户页面
@app.route('/admin/user/<int:user_id>/edit')
@login_required
@role_required('admin')
def edit_user(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取用户信息
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                flash('用户不存在', 'danger')
                return redirect(url_for('admin_users'))
            
            # 获取用户当前角色
            cursor.execute('''
                SELECT r.name 
                FROM roles r 
                INNER JOIN user_roles ur ON r.id = ur.role_id 
                WHERE ur.user_id = %s
            ''', (user_id,))
            user_roles = [row['name'] for row in cursor.fetchall()]
            
            # 获取所有角色
            cursor.execute('SELECT * FROM roles ORDER BY name')
            all_roles = cursor.fetchall()
            
            return render_template('admin/edit_user.html', user=user, user_roles=user_roles, all_roles=all_roles)
    finally:
        conn.close()

# 删除用户
@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    # 不能删除自己
    if user_id == session['user']['id']:
        flash('不能删除自己', 'danger')
        return redirect(url_for('admin_users'))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # 获取用户信息用于日志
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                flash('用户不存在', 'danger')
                return redirect(url_for('admin_users'))
            
            log_audit('delete_user', 'user', user_id, f'删除用户: {user["full_name"]}')
            
            # 删除用户角色关联
            cursor.execute('DELETE FROM user_roles WHERE user_id = %s', (user_id,))
            # 删除用户
            cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
            
            conn.commit()
            flash(f'用户 {user["full_name"]} 已删除', 'success')
            
            return redirect(url_for('admin_users'))
    finally:
        conn.close()

if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5001, debug=True)
