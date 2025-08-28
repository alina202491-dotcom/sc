# 弱密码检测工具

[![CI](https://github.com/username/weak-password-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/username/weak-password-checker/actions/workflows/ci.yml)
[![Security Scan](https://github.com/username/weak-password-checker/actions/workflows/security.yml/badge.svg)](https://github.com/username/weak-password-checker/actions/workflows/security.yml)
[![Code Quality](https://github.com/username/weak-password-checker/actions/workflows/code-quality.yml/badge.svg)](https://github.com/username/weak-password-checker/actions/workflows/code-quality.yml)
[![Performance](https://github.com/username/weak-password-checker/actions/workflows/performance.yml/badge.svg)](https://github.com/username/weak-password-checker/actions/workflows/performance.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)

这是一个用于检测多个主机弱密码的自动化脚本。脚本能够从表格文件读取主机列表，尝试访问登录页面，并使用常见弱密码进行登录尝试，最后生成检测结果报告。

## 功能特性

- 📊 支持从CSV和Excel文件读取主机列表
- 🌐 自动发现登录页面（支持多种常见路径）
- 🔐 支持HTTP基本认证和表单认证
- 💻 并发检测，提高效率
- 📝 生成详细的检测结果报告
- 🛡️ 内置常见弱密码字典
- ⚙️ 可配置的超时和并发参数

## 安装依赖

### 方法一：使用pip安装（推荐）

```bash
pip install -r requirements.txt
```

### 方法二：使用系统包管理器（Ubuntu/Debian）

```bash
sudo apt update
sudo apt install python3-pandas python3-requests python3-bs4 python3-openpyxl
```

### 方法三：使用虚拟环境

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

## 使用方法

### 1. 准备主机列表文件

创建包含要检测主机的表格文件，支持以下格式：

#### CSV格式示例 (hosts.csv)
```csv
host,description
192.168.1.1,路由器管理界面
192.168.1.100,服务器A
10.0.0.1,交换机管理
example.com,示例网站
https://admin.example.com,管理后台
```

#### Excel格式示例 (hosts.xlsx)
| 主机地址 | 描述 | 端口 |
|---------|------|------|
| 192.168.1.1 | 路由器管理界面 | 80 |
| 192.168.1.100 | 服务器A | 8080 |
| 10.0.0.1 | 交换机管理 | 443 |

**注意：** 脚本会自动识别包含主机信息的列，支持的列名关键词包括：host、ip、url、address、主机、地址等。

### 2. 运行脚本

#### 基本用法
```bash
python3 weak_password_checker.py hosts.csv
```

#### 高级用法
```bash
python3 weak_password_checker.py hosts.csv -o results.txt -w 20 -t 15
```

### 3. 参数说明

- `hosts_file`: 主机列表文件（必需参数）
- `-o, --output`: 输出文件名（默认：weak_login_results.txt）
- `-w, --workers`: 最大并发线程数（默认：10）
- `-t, --timeout`: 请求超时时间，单位秒（默认：10）

### 4. 查看结果

脚本执行完成后，会在当前目录生成结果文件，包含：
- 成功登录的主机详情
- 用户名和密码组合
- 认证类型（基本认证或表单认证）
- 统计信息和汇总

## 文件说明

- `weak_password_checker.py`: 主脚本文件
- `weak_passwords.txt`: 弱密码字典文件
- `requirements.txt`: Python依赖包列表
- `hosts_example.csv`: 主机列表示例文件
- `README.md`: 使用说明文档

## 脚本工作原理

1. **加载主机列表**: 从CSV或Excel文件读取主机地址
2. **发现登录页面**: 尝试常见的登录页面路径
3. **检测认证方式**: 支持HTTP基本认证和HTML表单认证
4. **弱密码尝试**: 使用内置字典进行用户名/密码组合尝试
5. **结果记录**: 记录成功登录的详细信息
6. **生成报告**: 输出格式化的检测结果

## 内置弱密码字典

脚本包含200+常见弱密码，包括：
- 数字序列：123456、12345678等
- 常见词汇：admin、password、root等
- 键盘模式：qwerty、123qwe等
- 系统默认：guest、demo、default等
- 品牌相关：cisco、huawei等

可以编辑 `weak_passwords.txt` 文件来自定义密码字典。

## 支持的登录方式

### HTTP基本认证
- 标准的HTTP Basic Authentication
- 常见于路由器、交换机管理界面

### HTML表单认证
- 自动识别登录表单
- 支持用户名/密码字段的多种命名方式
- 处理隐藏字段和CSRF令牌

## 安全说明

⚠️ **重要提醒**：
- 本工具仅用于安全测试和授权的渗透测试
- 请确保您有权限测试目标主机
- 不要在未经授权的系统上使用此工具
- 遵守当地法律法规和网络安全规定

## 常见问题

### Q: 脚本报告连接超时怎么办？
A: 可以增加超时时间参数，例如：`-t 30`

### Q: 如何提高检测速度？
A: 可以增加并发线程数，例如：`-w 50`（注意不要设置过大避免被目标服务器封锁）

### Q: 支持HTTPS网站吗？
A: 是的，脚本会自动处理HTTP和HTTPS，并忽略SSL证书验证

### Q: 如何添加自定义密码？
A: 编辑 `weak_passwords.txt` 文件，每行添加一个密码

### Q: 脚本会被WAF拦截吗？
A: 脚本包含基本的延迟机制，但对于有WAF保护的站点可能需要调整请求频率

## 🔄 CI/CD 和自动化

本项目使用 GitHub Actions 进行持续集成和自动化测试：

### 工作流状态
- **CI 工作流**: 在每次代码提交时自动运行测试
- **安全扫描**: 定期检查依赖漏洞和代码安全问题
- **代码质量**: 自动检查代码格式和质量
- **性能测试**: 定期运行性能基准测试
- **文档生成**: 自动更新项目文档

### 自动化功能
- 🤖 **Dependabot**: 自动更新依赖包
- 🎨 **代码格式化**: PR 时自动格式化代码
- 🔒 **安全扫描**: 每日自动安全检查
- 📦 **自动发布**: 标签推送时自动创建发布包

### 贡献指南
1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

所有 PR 都会自动运行 CI 检查，包括：
- ✅ 代码格式检查
- ✅ 单元测试
- ✅ 安全扫描
- ✅ 性能测试

## 许可证

本项目仅供学习和安全测试使用，使用者需自行承担相关责任。

## 更新日志

### v1.0.0
- 初始版本发布
- 支持CSV和Excel文件格式
- 实现HTTP基本认证和表单认证
- 内置200+弱密码字典
- 并发检测支持
- 详细结果报告