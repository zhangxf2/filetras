#!/usr/bin/env python3
import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, get_db_connection

def test_database():
    """测试数据库连接和基本数据"""
    print("=" * 60)
    print("数据库连接测试")
    print("=" * 60)
    
    try:
        conn = get_db_connection()
        print("✓ 数据库连接成功")
        
        with conn.cursor() as cursor:
            # 检查角色表
            cursor.execute("SELECT * FROM roles")
            roles = cursor.fetchall()
            print(f"\n角色列表:")
            for role in roles:
                print(f"  - {role['name']}: {role['description']}")
            
            # 检查用户表
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
            print(f"\n用户列表:")
            for user in users:
                print(f"  - ID: {user['id']}, 用户名: {user['username']}, 姓名: {user['full_name']}")
            
            # 检查用户角色关联
            cursor.execute("""
                SELECT u.username, r.name as role_name
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.id
                ORDER BY u.id
            """)
            user_roles = cursor.fetchall()
            print(f"\n用户角色关联:")
            current_user = None
            for ur in user_roles:
                if ur['username'] != current_user:
                    current_user = ur['username']
                    print(f"  - {current_user}:", end=" ")
                print(ur['role_name'], end=", ")
            print()
        
        conn.close()
        return True
    except Exception as e:
        print(f"✗ 数据库错误: {e}")
        import traceback
        traceback.print_exc()
        return False

def init_admin():
    """初始化admin用户"""
    print("\n" + "=" * 60)
    print("初始化管理员账号")
    print("=" * 60)
    
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 检查admin用户是否存在
            cursor.execute("SELECT * FROM users WHERE username = %s", ('admin',))
            admin_user = cursor.fetchone()
            
            if admin_user:
                print("✓ admin用户已存在")
                
                # 检查用户角色
                cursor.execute("""
                    SELECT r.name
                    FROM roles r
                    INNER JOIN user_roles ur ON r.id = ur.role_id
                    WHERE ur.user_id = %s
                """, (admin_user['id'],))
                roles = [r['name'] for r in cursor.fetchall()]
                print(f"  当前角色: {roles}")
                
                # 确保有admin和user角色
                if 'admin' not in roles:
                    cursor.execute("SELECT id FROM roles WHERE name = 'admin'")
                    admin_role = cursor.fetchone()
                    if admin_role:
                        cursor.execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (%s, %s)', 
                                       (admin_user['id'], admin_role['id']))
                        print("  ✓ 添加admin角色")
                
                if 'user' not in roles:
                    cursor.execute("SELECT id FROM roles WHERE name = 'user'")
                    user_role = cursor.fetchone()
                    if user_role:
                        cursor.execute('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (%s, %s)', 
                                       (admin_user['id'], user_role['id']))
                        print("  ✓ 添加user角色")
                
                conn.commit()
                
            else:
                print("创建admin用户...")
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
                    print("  ✓ 分配admin角色")
                
                # 分配user角色
                cursor.execute("SELECT id FROM roles WHERE name = 'user'")
                user_role = cursor.fetchone()
                if user_role:
                    cursor.execute('INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)', (admin_id, user_role['id']))
                    print("  ✓ 分配user角色")
                
                conn.commit()
                print(f"✓ admin用户创建成功 (ID: {admin_id})")
            
            # 显示最终状态
            cursor.execute("SELECT * FROM users WHERE username = %s", ('admin',))
            final_user = cursor.fetchone()
            
            cursor.execute("""
                SELECT r.name
                FROM roles r
                INNER JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = %s
            """, (final_user['id'],))
            final_roles = [r['name'] for r in cursor.fetchall()]
            
            print("\n" + "=" * 60)
            print("管理员账号信息")
            print("=" * 60)
            print(f"  用户名: admin")
            print(f"  密码: admin123")
            print(f"  姓名: {final_user['full_name']}")
            print(f"  角色: {final_roles}")
            print("\n请使用上述账号登录系统！")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ 错误: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("\n内网导外网数据文件审核系统 - 登录调试工具\n")
    
    success = test_database()
    if success:
        init_admin()
    else:
        print("\n请检查数据库配置是否正确！")
