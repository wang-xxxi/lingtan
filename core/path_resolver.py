"""统一路径解析 - 支持源码运行和 PyInstaller 打包两种模式"""
import os
import sys


def is_bundled():
    """检测是否在 PyInstaller 打包的 exe 中运行"""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def get_base_dir():
    """只读资源目录（模板、静态文件）
    打包模式: sys._MEIPASS (临时解压目录)
    源码模式: 项目根目录
    """
    if is_bundled():
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_app_dir():
    """获取 exe 或脚本所在目录（可写数据的基准目录）"""
    if is_bundled():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def get_data_dir():
    """可写数据目录（数据库等持久化数据）
    源码模式: <project>/data/
    打包模式: <exe_dir>/api_hunter_data/
    """
    if is_bundled():
        return _ensure_dir(os.path.join(get_app_dir(), 'api_hunter_data'))
    return _ensure_dir(os.path.join(get_base_dir(), 'data'))


def get_exports_dir():
    """导出文件目录
    源码模式: <project>/exports/
    打包模式: <exe_dir>/api_hunter_exports/
    """
    if is_bundled():
        return _ensure_dir(os.path.join(get_app_dir(), 'api_hunter_exports'))
    return _ensure_dir(os.path.join(get_base_dir(), 'exports'))


def get_reports_dir():
    """报告文件目录
    源码模式: <project>/data/reports/
    打包模式: <exe_dir>/api_hunter_data/reports/
    """
    return _ensure_dir(os.path.join(get_data_dir(), 'reports'))


def get_plugins_dir():
    """插件目录
    源码模式: <project>/plugins/
    打包模式: <exe_dir>/api_hunter_plugins/
    """
    if is_bundled():
        return _ensure_dir(os.path.join(get_app_dir(), 'api_hunter_plugins'))
    return _ensure_dir(os.path.join(get_base_dir(), 'plugins'))
