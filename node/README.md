# happypassword

本地加密密码库 CLI，模糊搜索，一键复制。零依赖（Node 自带 crypto），无需联网。

```bash
npm install -g happypassword    # 安装
npm update -g happypassword     # 更新
hpw add 名称        # 首次运行会引导你设置主密码
hpw -c 关键词       # 搜索并复制第一条密码到剪贴板
```

## 加密

- AES-256-GCM 认证加密，scrypt 派生主密码（N=2^15）
- 零网络请求，数据不出本机，密码库 `~/.hpw.vault.json`（隐藏文件）
- 主密码忘了无法找回

## 用法

```bash
hpw 关键词          # 模糊搜索并显示
hpw -c 关键词       # 搜索并复制（Windows 30s 后恢复剪贴板原值）
hpw add 名称        # 添加（密码栏回车 = 自动生成 20 位强密码）
hpw edit 名称       # 编辑条目（回车保留原值）
hpw ls / rm / gen   # 列表 / 删除 / 生成随机密码（8-128 位）
hpw import 文件.txt # 批量导入，每行：名称 [用户名] 密码
hpw export 文件.txt # 导出为明文 txt，注意保管
hpw passwd          # 更换主密码
hpw audit           # 密码体检：弱密码 / 重复密码
hpw -v              # 查看版本号
hpw --test          # 自检
```

平台：Windows / macOS（pbcopy）/ Linux（xclip / wl-copy）。

完整说明（安全模型、批量导入等）见仓库主 README：https://github.com/goehou/happypassword
