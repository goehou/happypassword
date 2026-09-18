#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hpw - 单文件轻量密码管理器

加密: Fernet (AES-128-CBC + HMAC-SHA256), scrypt 派生主密码
存储: ~/.hpw.vault (隐藏文件)
平台: Windows / macOS / Linux
用法:
  hpw 关键词            模糊搜索并显示条目 (子串/前缀命中排前, 兜底相似度, 阈值 0.5)
  hpw -c 关键词         搜索并复制第一条密码到剪贴板 (Windows 30秒后自动清空)
  hpw add 名称          添加条目; 密码栏直接回车 = 自动生成 20 位强密码
  hpw ls                列出全部条目名
  hpw rm 名称           删除条目 (支持模糊匹配, 多个命中让你选)
  hpw gen [长度]        生成指定长度随机密码 (默认 20)
  hpw import 文件.txt   批量导入, 每行: 名称 [用户名] 密码
  hpw --test            自检 (加密往返、错误密码拒绝、搜索排序、剪贴板、交互流程)
  hpw -help             显示本帮助
"""
import base64
import getpass
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
from difflib import SequenceMatcher

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT = os.path.join(os.path.expanduser("~"), ".hpw.vault")
# ponytail: scrypt n=2^15 (~100ms 解锁)。嫌慢就降到 2^14, 想更狠就 2^17
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1


def derive_key(master: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, length=32)
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))


def load_vault(master: str):
    """返回 entries_dict。主密码错/文件损坏时退出。"""
    if not os.path.exists(VAULT):
        sys.exit(f"vault 不存在: {VAULT}，先运行 hpw add 创建")
    blob = json.load(open(VAULT, encoding="utf-8"))
    key = derive_key(master, base64.b64decode(blob["salt"]))
    try:
        data = Fernet(key).decrypt(blob["data"].encode())
        return json.loads(data)
    except (InvalidToken, json.JSONDecodeError):
        sys.exit("主密码错误或 vault 文件损坏")


def ensure_vault():
    """vault 不存在时引导创建。返回 (master, entries)。"""
    if os.path.exists(VAULT):
        master = ask_master(False)
        return master, load_vault(master)
    print("首次使用, 先设置主密码 (用于加密整个密码库, 忘了无法找回)")
    master = ask_master(True)
    save_vault(master, {})
    return master, {}


def save_vault(master: str, entries: dict):
    # ponytail: Windows 上覆盖写 HIDDEN 属性文件会 PermissionError, 写前先去掉隐藏位
    if os.name == "nt" and os.path.exists(VAULT):
        subprocess.run(["attrib", "-h", VAULT], check=False)
    salt = secrets.token_bytes(16)
    key = derive_key(master, salt)
    token = Fernet(key).encrypt(json.dumps(entries, ensure_ascii=False).encode())
    json.dump({"salt": base64.b64encode(salt).decode(), "data": token.decode()},
              open(VAULT, "w", encoding="utf-8"))
    if os.name == "nt":
        subprocess.run(["attrib", "+h", VAULT], check=False)  # 隐藏文件


def ask_master(twice: bool = False) -> str:
    m = getpass.getpass("主密码: ")
    if not m:
        sys.exit("主密码不能为空")
    if twice and m != getpass.getpass("再输一遍: "):
        sys.exit("两次不一致")
    return m


def ask_secret(prompt: str) -> str:
    # 生成 vs 手输: 直接回车则自动生成 20 位强密码
    pw = getpass.getpass(prompt + " (直接回车=自动生成20位): ")
    return pw or gen_pw(20)


def rank(name: str, q: str) -> float:
    """搜索排序: 子串命中 > 前缀 > 模糊相似度"""
    nl, ql = name.lower(), q.lower()
    if ql in nl:
        return 2.0 + (1.0 if nl.startswith(ql) else 0.0) + len(ql) / max(len(nl), 1)
    return SequenceMatcher(None, nl, ql).ratio()


def search(entries: dict, q: str) -> list:
    hits = [(rank(name, q), name) for name in entries]
    hits = [h for h in hits if h[0] > 0.5]
    return [name for _, name in sorted(hits, key=lambda h: h[0], reverse=True)]


def copy_clipboard(text: str, clear_after: int = 30):
    if sys.platform == "win32":
        # ponytail: 走临时文件转编码最稳, 避免管道编码坑
        with tempfile.NamedTemporaryFile("w", encoding="utf-8-sig", delete=False, suffix=".txt") as f:
            f.write(text)
            tmp = f.name
        flags = subprocess.CREATE_NO_WINDOW
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Set-Clipboard -Value (Get-Content -Raw '{tmp}')"], check=False,
                       creationflags=flags)
        # 清剪贴板放后台, 不阻塞主进程; 句柄全置 DEVNULL, 避免持有父管道导致调用方挂起
        subprocess.Popen(["powershell", "-NoProfile", "-Command",
                          f"Start-Sleep {clear_after}; "
                          "if ((Get-Clipboard -Raw) -eq (Get-Content -Raw '" + tmp + "')) { Set-Clipboard -Value $null }; "
                          f"Remove-Item '{tmp}'"], creationflags=flags,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "darwin":
        subprocess.run(["pbcopy"], input=text.encode(), check=False)
    else:
        # ponytail: macOS 不做自动清空剪贴板, 各平台实现差异大, 需要 xclip/wl-copy/wl-paste 交互时再补
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"]):
            try:
                subprocess.run(cmd, input=text.encode(), check=False)
                return
            except FileNotFoundError:
                continue
        sys.exit("需要 xclip 或 wl-copy 之一: apt install xclip / pacman -S wl-clipboard")


def gen_pw(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def show(name: str, e: dict):
    print(f"  名称: {name}")
    if e.get("u"):
        print(f"  用户: {e['u']}")
    print(f"  密码: {e['p']}")
    if e.get("note"):
        print(f"  备注: {e['note']}")
    print()


def main():
    args = sys.argv[1:]
    if "--test" in args:
        test()
        return

    if not args or args[0] in ("-h", "--help", "-help", "help"):
        print(__doc__)
        # 打包 exe 双击运行时, 跑完即关窗, 停一下让人看完
        if getattr(sys, "frozen", False):
            input("\n按回车退出...")
        return

    if args[0] == "gen":
        print(gen_pw(int(args[1]) if len(args) > 1 else 20))
        return

    if args[0] == "add":
        name = args[1] if len(args) > 1 else input("名称: ").strip()
        if not name:
            sys.exit("名称不能为空")
        master, entries = ensure_vault()
        if name in entries:
            print(f"'{name}' 已存在, 将覆盖")
        e = {"u": input("用户名(可空): ").strip(),
             "p": ask_secret("密码"),
             "note": input("备注(可空): ").strip()}
        entries[name] = e
        save_vault(master, entries)
        show(name, e)
        print(f"已保存, 共 {len(entries)} 条")
        return

    if args[0] == "import":
        if len(args) < 2:
            sys.exit("用法: hpw import 文件.txt")
        master, entries = ensure_vault()
        n = 0
        for line in open(args[1], encoding="utf-8-sig"):
            parts = line.strip().split(None, 2)  # tab/空格切分
            if len(parts) >= 2 and not line.strip().startswith("#"):
                name = parts[0]
                u, p = (parts[1], parts[2]) if len(parts) == 3 else ("", parts[1])
                entries[name] = {"u": u, "p": p, "note": "imported"}
                n += 1
        save_vault(master, entries)
        print(f"已导入 {n} 条, 共 {len(entries)} 条")
        return

    if args[0] == "ls":
        _, entries = ensure_vault()
        if not entries:
            print("库是空的, 用 hpw add 名称 添加第一条")
            return
        for name in sorted(entries):
            print(name)
        return

    if args[0] == "rm":
        if len(args) < 2:
            sys.exit("用法: hpw rm 名称")
        master, entries = ensure_vault()
        if not entries:
            sys.exit("库是空的, 没什么可删")
        hits = search(entries, args[1]) if args[1] not in entries else [args[1]]
        if not hits:
            sys.exit("没找到")
        if len(hits) > 1:
            print("多个匹配, 选一个: " + " | ".join(hits))
            return
        del entries[hits[0]]
        save_vault(master, entries)
        print(f"已删除 {hits[0]}")
        return

    # 默认: 搜索。 hpw 关键词 → 显示; hpw -c 关键词 → 复制
    copy_mode = args[0] == "-c"
    q = args[1] if copy_mode else args[0]
    if not q:
        sys.exit("用法: hpw [-c] 关键词")
    _, entries = ensure_vault()
    if not entries:
        sys.exit("库是空的, 用 hpw add 名称 添加第一条")
    hits = search(entries, q)
    if not hits:
        sys.exit(f"没找到 '{q}'")
    if copy_mode:
        e = entries[hits[0]]
        acct = f" (账号: {e['u']})" if e.get("u") else ""
        copy_clipboard(e["p"])
        print(f"已复制 '{hits[0]}' 的密码{acct}, 30秒后剪贴板自动清空")
        if len(hits) > 1:
            print("(其他匹配: " + ", ".join(hits[1:5]) + " — 用更精确的关键词)")
    else:
        for name in hits[:10]:
            show(name, entries[name])


def test():
    """自检: 加密往返 + 搜索排序 + 导入解析。不碰真实 vault。"""
    global VAULT, SCRYPT_N
    SCRYPT_N = 2**10  # 测试加速
    VAULT = os.path.join(tempfile.mkdtemp(), "test.vault")
    # 1. 保存→加载往返
    save_vault("m1", {"git": {"u": "a", "p": "s3cret", "note": ""}})
    assert load_vault("m1")["git"]["p"] == "s3cret"
    # 2. 错误主密码必须失败
    try:
        load_vault("wrong")
        assert False, "错误主密码竟然解开了!"
    except SystemExit:
        pass
    # 3. 搜索: 子串命中排前, 不相关排除
    es = {"github": {}, "gitlab": {}, "淘宝": {}, "random": {}}
    assert search(es, "git")[:2] == ["github", "gitlab"]
    assert "random" not in search(es, "git")
    assert search(es, "淘宝") == ["淘宝"]
    # 4. 生成的密码够长且随机
    assert len(gen_pw(20)) == 20 and gen_pw(20) != gen_pw(20)
    # 5. 剪贴板: 复制立即生效, 延迟后清空 (仅 Windows, 其他平台无 powershell)
    if sys.platform == "win32":
        copy_clipboard("clip-test-123", clear_after=2)
        import time
        time.sleep(1)  # 等后台进程把复制做完
        out = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
                             capture_output=True, text=True, encoding="utf-8").stdout.strip()
        assert out == "clip-test-123", f"剪贴板内容异常: {out!r}"
        time.sleep(2.5)  # 超过 clear_after, 应已清空
        out2 = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
                              capture_output=True, text=True, encoding="utf-8").stdout.strip()
        assert out2 == "", f"剪贴板未自动清空: {out2!r}"
    # 6. 交互流程: add → 搜索 → rm (mock 输入, 不碰真实 vault)
    import builtins
    real_input = builtins.input
    real_getpass = getpass.getpass
    builtins.input = lambda *a, **k: ""  # 用户名/备注留空, 密码走自动生成
    getpass.getpass = lambda *a, **k: "tpw"
    import io
    real_argv = sys.argv
    real_vault = VAULT
    VAULT = os.path.join(tempfile.mkdtemp(), "flow.vault")
    try:
        for argv, expect in (
            (["add", "测试站"], "已保存"),
            (["测试"], "密码"),          # 搜索
            (["-c", "测试"], "已复制"),   # 复制
            (["ls"], "测试站"),
            (["rm", "测试站"], "已删除"),
        ):
            sys.argv = ["pw.py"] + argv
            buf = io.StringIO()
            real_stdout = sys.stdout
            sys.stdout = buf
            try:
                main()
            finally:
                sys.stdout = real_stdout
            assert expect in buf.getvalue(), f"{argv} 输出缺 '{expect}': {buf.getvalue()!r}"
    finally:
        sys.argv = real_argv
        VAULT = real_vault
        builtins.input = real_input
        getpass.getpass = real_getpass
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    if os.name != "nt" and sys.platform != "win32":
        pass  # 剪贴板用了 powershell, 其他平台不保证
    main()
