from termcolor import cprint
import datetime
import functools
import os


class LogPrinter:
    """节点打印函数生成器"""

    def __init__(self, name, enabled=True, color=True, show_time=True, log_file=None):
        """
        初始化节点打印器

        参数:
            name (str): 节点名称
            enabled (bool): 是否启用打印
            color (bool): 是否使用彩色输出
            show_time (bool): 是否显示时间戳
            log_file (str): 日志文件路径，None表示不记录日志
        """
        self.name = name
        self.enabled = enabled
        self.color = color
        self.show_time = show_time
        self.log_file = log_file
        self.log_handle = None

        # 为节点选择一个固定的颜色
        colors = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']
        self.node_color = colors[hash(name) % len(colors)]

        # 原始print函数
        self.orig_print = print

        # 创建打印函数
        self.print = self._create_print_function()

        # 如果启用日志，打开日志文件
        if self.log_file:
            self._open_log_file()

    def _create_print_function(self):
        """创建打印函数"""

        def print_func(*args, **kwargs):
            if not self.enabled:
                return

            prefix = ""

            # 添加时间戳
            if self.show_time:
                timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                prefix += f"[{timestamp}] "

            # 添加节点名
            prefix += f"[{self.name}] "

            # 打印到控制台
            if self.color:
                cprint(prefix, self.node_color, end="")
            else:
                self.orig_print(prefix, end="")

            self.orig_print(*args, **kwargs)

            # 写入日志
            if self.log_handle:
                print(prefix, *args, file=self.log_handle, **kwargs)
                self.log_handle.flush()

        # 将控制方法绑定到打印函数
        print_func.enable = self.enable
        print_func.disable = self.disable
        print_func.toggle = self.toggle
        print_func.set_log_file = self.set_log_file
        print_func.close_log = self.close_log

        return print_func

    def enable(self):
        """启用打印"""
        self.enabled = True
        return self

    def disable(self):
        """禁用打印"""
        self.enabled = False
        return self

    def toggle(self):
        """切换打印状态"""
        self.enabled = not self.enabled
        return self.enabled

    def set_log_file(self, file_path):
        """设置日志文件"""
        self.close_log()  # 关闭现有日志
        self.log_file = file_path
        if file_path:
            self._open_log_file()
        return self

    def _open_log_file(self):
        """打开日志文件"""
        try:
            # 确保目录存在
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)

            self.log_handle = open(self.log_file, 'a')
        except Exception as e:
            self.orig_print(f"Error opening log file: {e}")
            self.log_file = None

    def close_log(self):
        """关闭日志文件"""
        if self.log_handle:
            self.log_handle.close()
            self.log_handle = None
        return self

    def __del__(self):
        """析构函数，确保日志文件被关闭"""
        self.close_log()
