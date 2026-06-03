#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
灵探 打包脚本
将项目打包为单个 .exe 文件，双击即可运行
"""
import os
import sys
import subprocess
import shutil

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(PROJECT_DIR, 'dist')
BUILD_DIR = os.path.join(PROJECT_DIR, 'build')

# Colors
G = '\033[92m'
R = '\033[91m'
Y = '\033[93m'
C = '\033[96m'
X = '\033[0m'


def log(msg, color=G):
    print(f"{color}{msg}{X}")


def ensure_pyinstaller():
    """确保 PyInstaller 已安装"""
    try:
        import PyInstaller
        return True
    except ImportError:
        log("[*] 正在安装 PyInstaller...", Y)
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', 'pyinstaller', '-q'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            log("[+] PyInstaller 安装成功")
            return True
        except subprocess.CalledProcessError:
            log("[-] PyInstaller 安装失败", R)
            return False


def clean():
    """清理旧的构建产物"""
    for d in [BUILD_DIR, DIST_DIR]:
        if os.path.exists(d):
            log(f"[*] 清理 {os.path.basename(d)}/", Y)
            shutil.rmtree(d)
    spec = os.path.join(PROJECT_DIR, '灵探.spec')
    if os.path.exists(spec):
        os.remove(spec)


def build():
    """执行打包"""
    log("\n[*] 开始打包 灵探 ...", C)
    log("    这可能需要几分钟，请耐心等待\n", Y)

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--onefile',
        '--name', 'LingTan',
        '--add-data', f'web{os.pathsep}web',
        '--hidden-import', 'flask',
        '--hidden-import', 'requests',
        '--hidden-import', 'bs4',
        '--hidden-import', 'lxml',
        '--hidden-import', 'jinja2',
        '--hidden-import', 'werkzeug',
        '--hidden-import', 'urllib3',
        '--hidden-import', 'charset_normalizer',
        '--hidden-import', 'idna',
        '--hidden-import', 'certifi',
        '--hidden-import', 'soupsieve',
        '--hidden-import', 'markupsafe',
        '--hidden-import', 'click',
        '--hidden-import', 'blinker',
        '--hidden-import', 'core.path_resolver',
        '--hidden-import', 'core.database',
        '--hidden-import', 'core.app',
        '--hidden-import', 'core.analyzer',
        '--hidden-import', 'core.crawler',
        '--hidden-import', 'core.js_analyzer',
        '--hidden-import', 'core.apk_analyzer',
        '--hidden-import', 'core.har_analyzer',
        '--hidden-import', 'core.exporter',
        '--hidden-import', 'core.fuzzer',
        '--hidden-import', 'core.spec_generator',
        '--hidden-import', 'core.scanner_utils',
        '--hidden-import', 'core.site_crawler',
        '--hidden-import', 'core.site_analyzer',
        '--hidden-import', 'core.script_generator',
        '--hidden-import', 'core.proxy_server',
        '--hidden-import', 'core.graphql_analyzer',
        '--hidden-import', 'core.websocket_detector',
        '--hidden-import', 'core.report_generator',
        '--hidden-import', 'core.task_manager',
        '--hidden-import', 'core.plugin_manager',
        '--hidden-import', 'core.param_miner',
        '--hidden-import', 'core.auth_detector',
        '--hidden-import', 'core.header_auditor',
        '--hidden-import', 'core.subdomain_enum',
        '--hidden-import', 'core.spec_importer',
        '--hidden-import', 'core.traffic_analyzer',
        '--hidden-import', 'core.session_manager',
        '--hidden-import', 'core.page_classifier',
        '--hidden-import', 'core.data_extractor',
        '--hidden-import', 'core.pagination_detector',
        '--hidden-import', 'core.spa_adapter',
        '--hidden-import', 'core.crawl_rules',
        '--collect-all', 'lxml',
        '--collect-all', 'bs4',
        '--noconfirm',
        '--console',
        os.path.join(PROJECT_DIR, 'run.py'),
    ]

    result = subprocess.run(cmd, cwd=PROJECT_DIR)

    if result.returncode == 0:
        exe_path = os.path.join(DIST_DIR, 'LingTan.exe')
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            log(f"\n{'=' * 50}")
            log(f"[+] 打包成功!")
            log(f"[+] 可执行文件: {exe_path}")
            log(f"[+] 文件大小: {size_mb:.1f} MB")
            log(f"{'=' * 50}")
            log(f"\n使用方法:")
            log(f"  1. 将 LingTan.exe 复制到任意目录")
            log(f"  2. 双击运行即可")
            log(f"  3. 数据保存在 exe 同目录的 api_hunter_data/ 下")
        else:
            log("[-] 打包似乎成功但未找到 exe 文件", R)
    else:
        log(f"\n[-] 打包失败 (exit code: {result.returncode})", R)


def main():
    os.chdir(PROJECT_DIR)

    log(f"""
{C}{'=' * 50}
  灵探 打包工具
  将程序打包为独立可执行文件
{'=' * 50}{X}
""")

    if not ensure_pyinstaller():
        return

    clean()
    build()


if __name__ == '__main__':
    main()
