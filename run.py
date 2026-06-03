#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
灵探 - 接口发现与分析系统
主入口文件 - 双击即可启动
"""

import os
import sys
import time
import subprocess
import importlib
import webbrowser
import threading

# Detect bundled exe mode
BUNDLED = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')

if not BUNDLED:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Color codes for terminal output
COLORS = {
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'MAGENTA': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
}

BANNER = r"""
{cyan}{bold}
    ___    ____  ____  __  __
   /   |  / __ \/ __ \/ / / /
  / /| | / /_/ / / / / /_/ /
 / ___ |/ ____/ /_/ / __  /
/_/  |_/_/    \____/_/ /_/
          {yellow}H U N T E R{reset}
{white}  ━━ 接口发现与分析系统 ━━{reset}
{dim}  自动发现 · 智能分析 · 多格式支持{reset}
""".format(
    cyan=COLORS['CYAN'],
    yellow=COLORS['YELLOW'],
    white=COLORS['WHITE'],
    bold=COLORS['BOLD'],
    reset=COLORS['RESET'],
    dim='',
)


def check_and_install_dependencies():
    """Check and install required dependencies"""
    if BUNDLED:
        return True

    required = {
        'flask': 'flask',
        'requests': 'requests',
        'bs4': 'beautifulsoup4',
        'lxml': 'lxml',
    }

    missing = []
    for module, package in required.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"{COLORS['YELLOW']}[*] 正在安装缺少的依赖: {', '.join(missing)}{COLORS['RESET']}")
        for package in missing:
            try:
                subprocess.check_call(
                    [sys.executable, '-m', 'pip', 'install', package, '-q'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                print(f"{COLORS['GREEN']}[+] {package} 安装成功{COLORS['RESET']}")
            except subprocess.CalledProcessError:
                print(f"{COLORS['RED']}[-] {package} 安装失败，请手动运行: pip install {package}{COLORS['RESET']}")
                return False
    return True


def find_available_port(start=8888, max_tries=20):
    """Find an available port"""
    import socket
    for port in range(start, start + max_tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None


def open_browser_delayed(url, delay=2):
    """Open browser after delay"""
    time.sleep(delay)
    webbrowser.open(url)


def main():
    if not BUNDLED:
        print(BANNER)

    # Install dependencies (skip in bundled mode)
    if not check_and_install_dependencies():
        print(f"\n{COLORS['RED']}[-] 依赖安装失败，按回车键退出...{COLORS['RESET']}")
        input()
        sys.exit(1)

    # Find available port
    port = find_available_port(8888)
    if not port:
        print(f"{COLORS['RED']}[-] 无法找到可用端口{COLORS['RESET']}")
        input()
        sys.exit(1)

    url = f'http://localhost:{port}'

    print(f"{COLORS['GREEN']}[+] 系统启动成功!{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}    访问地址: {COLORS['CYAN']}{url}{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}    按 {COLORS['RED']}Ctrl+C{COLORS['WHITE']} 停止服务{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}    {'━' * 40}{COLORS['RESET']}\n")

    # Auto-open browser
    threading.Thread(target=open_browser_delayed, args=(url,), daemon=True).start()

    # Start Flask app
    from core.app import app
    try:
        app.run(host='127.0.0.1', port=port, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print(f"\n{COLORS['YELLOW']}[*] 服务已停止{COLORS['RESET']}")
    except Exception as e:
        print(f"\n{COLORS['RED']}[-] 服务异常: {e}{COLORS['RESET']}")
        if not BUNDLED:
            input()


if __name__ == '__main__':
    main()
