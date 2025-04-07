import functools

# 监听回调


class Passive_detect_by_record():
    def __init__(self, target, methods_to_listen):
        """
        :param target: 目标对象
        :param methods_to_listen: 需要监听的方法列表，例如 ["method_x", "component1.action1"]
        """
        self.target = target  # 目标对象
        self.methods_to_listen = set(methods_to_listen)  # 需要监听的方法
        self.listener = self.node_listener  # 监听回调函数
        self._wrap_methods()  # 代理方法
        self.datalist = []

    def set_listener(self):
        """设置监听回调函数"""
        self.listener = self.node_listener

    def _wrap_methods(self):
        """代理 target 本身及其成员变量的指定方法"""
        for method_path in self.methods_to_listen:
            parts = method_path.split(".")  # 解析成员变量路径
            if len(parts) == 1:
                # 监听 target 本身的方法，例如 "method_x"
                self._wrap_single_method(self.target, method_path)
            elif len(parts) == 2:
                # 监听 target 内部成员的方法，例如 "component1.action1"
                attr_name, method_name = parts
                if hasattr(self.target, attr_name):
                    attr_obj = getattr(self.target, attr_name)
                    self._wrap_single_method(attr_obj, method_name)
            else:
                raise ValueError(f"格式错误: {method_path}，应为 '方法名' 或 '成员变量.方法名'")

    def _wrap_single_method(self, obj, method_name):
        """代理某个对象的单个方法"""
        if hasattr(obj, method_name):
            original_method = getattr(obj, method_name)
            if callable(original_method):  # 确保是方法
                def wrapper(*args, **kwargs):
                    if self.listener:
                        self.listener(args, kwargs)  # 触发监听器
                    return original_method(*args, **kwargs)  # 调用原方法

                setattr(obj, method_name, wrapper)  # 替换原方法




    def node_listener(self, args, kwargs):

        from datetime import datetime

        if len(args) == 1 and isinstance(args[0], tuple):
            # 形式: (packet, (host, port))
            packet, (host, port) = args[0]
        elif len(args) == 3:
            # 形式: packet, host, port
            packet, host, port = args
        else:
            raise ValueError("Unsupported data format")

        packet_size = len(packet)
        # 获取当前日期和时间
        now = datetime.now()

        self.datalist.append([now, packet_size, host, port, packet])
        print(len(self.datalist))
        if len(self.datalist) >= 50:
            self.record_data()

    def record_data(self):

        self.datalist.clear()


