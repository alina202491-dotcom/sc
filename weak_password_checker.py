#!/usr/bin/env python3
"""
弱密码检测脚本
支持从表格文件读取主机列表，尝试弱密码登录，并生成结果报告
"""

import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import time
import os
import sys
from urllib.parse import urljoin, urlparse
import warnings
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from datetime import datetime

# 禁用SSL警告
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class WeakPasswordChecker:
    def __init__(self, hosts_file, output_file='weak_login_results.txt', max_workers=10, timeout=10):
        self.hosts_file = hosts_file
        self.output_file = output_file
        self.max_workers = max_workers
        self.timeout = timeout
        self.successful_logins = []
        self.lock = threading.Lock()
        
        # 常见弱密码列表
        self.weak_passwords = self.load_weak_passwords()
        
        # 常见用户名
        self.usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'sa', 'oracle', 'postgres', 'mysql', 'demo', 'default',
            'operator', 'manager', 'support', 'service', 'web', 'www'
        ]
        
        # 常见登录页面路径
        self.login_paths = [
            '/login', '/admin', '/admin/login', '/administrator', 
            '/login.php', '/admin.php', '/wp-admin', '/admin/index.php',
            '/management', '/manager', '/console', '/dashboard',
            '/signin', '/sign-in', '/auth', '/authenticate',
            '/portal', '/webui', '/ui', '/web'
        ]
        
    def load_weak_passwords(self):
        """加载弱密码字典"""
        passwords = [
            'admin', 'password', '123456', '12345678', '123456789',
            'admin123', 'password123', 'root', '1234', '12345',
            'qwerty', 'abc123', 'Password1', 'admin@123', 'root123',
            'administrator', '1qaz2wsx', 'welcome', 'letmein', 'monkey',
            'dragon', '111111', 'iloveyou', 'sunshine', 'master',
            'hello', 'freedom', 'whatever', 'qazwsx', 'trustno1',
            '654321', 'jordan23', 'harley', 'password1', '1234567',
            'soccer', 'rock', 'princess', 'anthony', 'mickey',
            'shadow', 'cookie', 'buster', 'taylor', 'northern',
            'charles', 'carlos', 'money', 'love', 'test',
            'guest', 'demo', '', 'default', 'changeme',
            'system', 'oracle', 'sa', 'god', 'sex',
            'secret', 'business', 'computer', 'owner', 'home'
        ]
        
        # 尝试从文件加载额外密码
        password_file = 'weak_passwords.txt'
        if os.path.exists(password_file):
            try:
                with open(password_file, 'r', encoding='utf-8') as f:
                    file_passwords = [line.strip() for line in f if line.strip()]
                    passwords.extend(file_passwords)
                    print(f"从 {password_file} 加载了 {len(file_passwords)} 个额外密码")
            except Exception as e:
                print(f"警告：无法读取密码文件 {password_file}: {e}")
        
        return list(set(passwords))  # 去重
    
    def load_hosts(self):
        """从表格文件加载主机列表"""
        try:
            if self.hosts_file.endswith('.csv'):
                df = pd.read_csv(self.hosts_file)
            elif self.hosts_file.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(self.hosts_file)
            else:
                raise ValueError("不支持的文件格式，请使用 CSV 或 Excel 文件")
            
            # 查找包含主机信息的列
            host_columns = []
            for col in df.columns:
                col_lower = col.lower()
                if any(keyword in col_lower for keyword in ['host', 'ip', 'url', 'address', '主机', '地址']):
                    host_columns.append(col)
            
            if not host_columns:
                print("警告：未找到主机列，尝试使用第一列作为主机列表")
                host_columns = [df.columns[0]]
            
            hosts = []
            for col in host_columns:
                hosts.extend(df[col].dropna().tolist())
            
            # 清理和标准化主机地址
            cleaned_hosts = []
            for host in hosts:
                host = str(host).strip()
                if host and host.lower() not in ['nan', 'none', '']:
                    # 如果没有协议，添加 http://
                    if not host.startswith(('http://', 'https://')):
                        # 尝试 https 首先
                        cleaned_hosts.append(f'https://{host}')
                        cleaned_hosts.append(f'http://{host}')
                    else:
                        cleaned_hosts.append(host)
            
            print(f"从 {self.hosts_file} 加载了 {len(cleaned_hosts)} 个主机地址")
            return list(set(cleaned_hosts))  # 去重
            
        except Exception as e:
            print(f"错误：无法读取主机文件 {self.hosts_file}: {e}")
            sys.exit(1)
    
    def normalize_url(self, url):
        """标准化URL"""
        if not url.startswith(('http://', 'https://')):
            return f'http://{url}'
        return url
    
    def find_login_page(self, base_url):
        """查找登录页面"""
        session = requests.Session()
        session.verify = False
        
        for path in self.login_paths:
            try:
                url = urljoin(base_url, path)
                response = session.get(url, timeout=self.timeout, allow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    # 检查是否包含登录相关的元素
                    login_indicators = [
                        'password', 'login', 'username', 'signin', 'sign-in',
                        'auth', 'authenticate', 'form', 'input type="password"',
                        '用户名', '密码', '登录', '登陆'
                    ]
                    
                    if any(indicator in content for indicator in login_indicators):
                        return url, response
                        
            except Exception:
                continue
        
        # 如果没有找到专门的登录页面，尝试基本URL
        try:
            response = session.get(base_url, timeout=self.timeout, allow_redirects=True)
            if response.status_code == 200:
                content = response.text.lower()
                login_indicators = [
                    'password', 'login', 'username', 'signin', 'sign-in',
                    'auth', 'authenticate', 'form', 'input type="password"',
                    '用户名', '密码', '登录', '登陆'
                ]
                
                if any(indicator in content for indicator in login_indicators):
                    return base_url, response
        except Exception:
            pass
        
        return None, None
    
    def try_basic_auth(self, url, username, password):
        """尝试HTTP基本认证"""
        try:
            response = requests.get(
                url, 
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            # 检查是否认证成功
            if response.status_code == 200:
                # 进一步检查内容，确保不是登录页面
                content = response.text.lower()
                if not any(indicator in content for indicator in ['login', 'password', 'username', 'signin', 'unauthorized']):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def try_form_auth(self, login_url, login_response, username, password):
        """尝试表单认证"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(login_response.text, 'html.parser')
            
            # 查找登录表单
            forms = soup.find_all('form')
            
            for form in forms:
                # 查找用户名和密码字段
                username_field = None
                password_field = None
                
                inputs = form.find_all('input')
                for inp in inputs:
                    inp_type = inp.get('type', '').lower()
                    inp_name = inp.get('name', '').lower()
                    inp_id = inp.get('id', '').lower()
                    
                    # 识别用户名字段
                    if (inp_type in ['text', 'email'] or 
                        any(keyword in inp_name for keyword in ['user', 'login', 'email', 'account']) or
                        any(keyword in inp_id for keyword in ['user', 'login', 'email', 'account'])):
                        username_field = inp.get('name') or inp.get('id')
                    
                    # 识别密码字段
                    elif (inp_type == 'password' or
                          any(keyword in inp_name for keyword in ['pass', 'pwd']) or
                          any(keyword in inp_id for keyword in ['pass', 'pwd'])):
                        password_field = inp.get('name') or inp.get('id')
                
                if username_field and password_field:
                    # 准备表单数据
                    form_data = {}
                    
                    # 添加所有隐藏字段
                    for inp in inputs:
                        if inp.get('type') == 'hidden' and inp.get('name'):
                            form_data[inp.get('name')] = inp.get('value', '')
                    
                    # 添加用户名和密码
                    form_data[username_field] = username
                    form_data[password_field] = password
                    
                    # 获取表单提交URL
                    action = form.get('action')
                    if action:
                        submit_url = urljoin(login_url, action)
                    else:
                        submit_url = login_url
                    
                    # 提交表单
                    session = requests.Session()
                    session.verify = False
                    
                    response = session.post(
                        submit_url,
                        data=form_data,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    
                    # 检查登录是否成功
                    if response.status_code == 200:
                        content = response.text.lower()
                        success_indicators = [
                            'dashboard', 'welcome', 'logout', 'admin panel',
                            'control panel', 'management', 'success',
                            '欢迎', '控制台', '管理', '退出'
                        ]
                        
                        fail_indicators = [
                            'login failed', 'invalid', 'incorrect', 'error',
                            'wrong', 'denied', 'unauthorized', 'try again',
                            '登录失败', '用户名或密码错误', '无效', '错误'
                        ]
                        
                        # 如果包含成功指示符且不包含失败指示符
                        if (any(indicator in content for indicator in success_indicators) and
                            not any(indicator in content for indicator in fail_indicators)):
                            return True
                        
                        # 如果响应URL发生变化（可能是重定向到仪表板）
                        if response.url != submit_url and 'login' not in response.url:
                            return True
                            
        except ImportError:
            print("警告：未安装 beautifulsoup4，跳过表单认证尝试")
        except Exception as e:
            pass
        
        return False
    
    def check_host(self, host):
        """检查单个主机的弱密码"""
        results = []
        
        try:
            print(f"正在检查: {host}")
            
            # 查找登录页面
            login_url, login_response = self.find_login_page(host)
            
            if not login_url:
                print(f"  未找到登录页面: {host}")
                return results
            
            print(f"  找到登录页面: {login_url}")
            
            # 尝试弱密码组合
            for username in self.usernames:
                for password in self.weak_passwords:
                    try:
                        # 尝试HTTP基本认证
                        if self.try_basic_auth(login_url, username, password):
                            result = {
                                'host': host,
                                'login_url': login_url,
                                'username': username,
                                'password': password,
                                'auth_type': 'Basic Auth',
                                'success': True
                            }
                            results.append(result)
                            print(f"  ✓ 成功登录: {username}:{password} (Basic Auth)")
                            continue
                        
                        # 尝试表单认证
                        if login_response and self.try_form_auth(login_url, login_response, username, password):
                            result = {
                                'host': host,
                                'login_url': login_url,
                                'username': username,
                                'password': password,
                                'auth_type': 'Form Auth',
                                'success': True
                            }
                            results.append(result)
                            print(f"  ✓ 成功登录: {username}:{password} (Form Auth)")
                            continue
                        
                        # 添加延迟避免被封锁
                        time.sleep(0.1)
                        
                    except Exception as e:
                        continue
            
            if not results:
                print(f"  未发现弱密码: {host}")
                
        except Exception as e:
            print(f"  检查失败: {host} - {e}")
        
        return results
    
    def save_results(self, all_results):
        """保存结果到文件"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(f"弱密码检测结果报告\n")
            f.write(f"生成时间: {timestamp}\n")
            f.write(f"{'='*50}\n\n")
            
            if all_results:
                f.write(f"发现 {len(all_results)} 个弱密码登录:\n\n")
                
                for i, result in enumerate(all_results, 1):
                    f.write(f"{i}. 主机: {result['host']}\n")
                    f.write(f"   登录页面: {result['login_url']}\n")
                    f.write(f"   用户名: {result['username']}\n")
                    f.write(f"   密码: {result['password']}\n")
                    f.write(f"   认证类型: {result['auth_type']}\n")
                    f.write(f"   {'-'*40}\n\n")
                
                # 统计信息
                f.write(f"\n统计信息:\n")
                f.write(f"总检测主机数: {len(set(r['host'] for r in all_results))}\n")
                f.write(f"成功登录数: {len(all_results)}\n")
                
                # 按主机分组
                hosts_summary = {}
                for result in all_results:
                    host = result['host']
                    if host not in hosts_summary:
                        hosts_summary[host] = []
                    hosts_summary[host].append(f"{result['username']}:{result['password']}")
                
                f.write(f"\n按主机汇总:\n")
                for host, credentials in hosts_summary.items():
                    f.write(f"  {host}: {', '.join(credentials)}\n")
                    
            else:
                f.write("未发现任何弱密码登录。\n")
        
        print(f"\n结果已保存到: {self.output_file}")
    
    def run(self):
        """运行弱密码检测"""
        print("=" * 60)
        print("弱密码检测工具启动")
        print("=" * 60)
        
        # 加载主机列表
        hosts = self.load_hosts()
        if not hosts:
            print("错误：没有找到有效的主机地址")
            return
        
        print(f"将检测 {len(hosts)} 个主机")
        print(f"使用 {len(self.usernames)} 个用户名和 {len(self.weak_passwords)} 个密码")
        print(f"最大并发数: {self.max_workers}")
        print("-" * 60)
        
        all_results = []
        
        # 使用线程池并发检测
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_host = {executor.submit(self.check_host, host): host for host in hosts}
            
            # 收集结果
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    results = future.result()
                    if results:
                        with self.lock:
                            all_results.extend(results)
                except Exception as e:
                    print(f"检测主机 {host} 时发生错误: {e}")
        
        print("-" * 60)
        print(f"检测完成！共发现 {len(all_results)} 个弱密码登录")
        
        # 保存结果
        self.save_results(all_results)
        
        # 显示摘要
        if all_results:
            print("\n发现的弱密码登录:")
            for result in all_results:
                print(f"  {result['host']} - {result['username']}:{result['password']} ({result['auth_type']})")
        
        return all_results

def main():
    parser = argparse.ArgumentParser(description='弱密码检测工具')
    parser.add_argument('hosts_file', help='包含主机列表的文件 (CSV或Excel)')
    parser.add_argument('-o', '--output', default='weak_login_results.txt', help='输出文件名')
    parser.add_argument('-w', '--workers', type=int, default=10, help='最大并发线程数')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间(秒)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.hosts_file):
        print(f"错误：文件 {args.hosts_file} 不存在")
        sys.exit(1)
    
    checker = WeakPasswordChecker(
        hosts_file=args.hosts_file,
        output_file=args.output,
        max_workers=args.workers,
        timeout=args.timeout
    )
    
    checker.run()

if __name__ == "__main__":
    main()