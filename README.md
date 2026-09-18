# HappyPassword

本地加密密码库，模糊搜索，一键复制。单文件、零依赖、无需联网。

```
❯ hpw -c vpn
主密码: ********
已复制 'vpn' 的密码, 30秒后剪贴板自动清空
```

两个实现，功能一致，选一个：

| | [python/](./python) | [node/](./node) |
|---|---|---|
| 依赖 | Python 3 + cryptography | Node ≥16，零依赖 |
| 安装 | `pip install cryptography` 或下载 exe | `npm i -g happypassword` |
| 打包 | PyInstaller → 单 exe（见 `python/build.cmd`） | 无需打包 |
| 密码库 | `~/.hpw.vault` | `~/.hpw.vault.json` |

> 两版密码库格式不互通，各自独立存储。

## 安装与更新

**Node 版（零依赖，推荐）：**

```bash
npm install -g happypassword    # 安装
npm update -g happypassword     # 更新
```

**Python 版：**

```bash
pip install cryptography        # 安装唯一依赖，或直接下载打包好的 exe
python pw.py --test             # 装完自检
```

命令与下表用法一致，把 `hpw` 换成 `python pw.py`（或 `hpw.exe`）即可：

```bash
python pw.py 关键词             # 模糊搜索并显示
python pw.py -c 关键词          # 搜索并复制第一条密码
```

## 用法（两版一致）

```bash
hpw 关键词          # 模糊搜索并显示（子串/前缀命中排前）
hpw -c 关键词       # 搜索并复制第一条密码到剪贴板
hpw add 名称        # 添加条目（密码栏直接回车 = 自动生成 20 位强密码）
hpw ls              # 列出全部条目名
hpw rm 名称         # 删除条目
hpw gen 24          # 生成 24 位随机密码
hpw import 文件.txt # 批量导入，每行：名称 [用户名] 密码
hpw --test          # 自检
```

### 批量导入

把散落在微信文件传输助手 / 记事本里的密码整理成 txt，每行一条：

```
名称 [用户名] 密码
微信  mypassword123
GitHub  me@x.com  s3cret!pass
```

（名称必填，用户名可省，tab 或空格分隔，`#` 开头的行跳过）

## 安全模型（Security Model）

- **加密**：AES-256-GCM 认证加密（Node 版）/ Fernet（AES-128-CBC + HMAC-SHA256，Python 版），整个密码库加密存储
- **密钥派生**：scrypt（N=2^15, r=8, p=1），暴力破解主密码成本高
- **零网络**：无任何网络请求，grep 源码可验证——数据永远不出本机
- **剪贴板**：Windows 上复制后 30 秒自动清空
- **主密码无后门**：忘了无法找回，密码库即作废
- 密码库是隐藏文件，换电脑拷走它 + 主密码即可恢复

## 平台

| 功能 | Windows | macOS | Linux |
|---|---|---|---|
| 加密 / 搜索 / 增删 | ✅ | ✅ | ✅ |
| 一键复制 | ✅（30s 自动清空） | ✅（pbcopy） | ✅（xclip / wl-copy） |

## 开发

```bash
python/python pw.py --test     # Python 版自检
node/node hpw.js --test        # Node 版自检
python/build.cmd               # PyInstaller 打包，输出 python/dist/hpw.exe
```

MIT License
