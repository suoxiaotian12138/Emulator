import json
from pathlib import Path
from collections import namedtuple

class JSONReader(object):
    TYPE_CASTS = {
        "NOISE_LENGTH": int,
        "EXP_PARAMS_LOOPS": float,
        "EXP_PARAMS_DROP": float,
        "EXP_PARAMS_PAYLOAD": float,
        "EXP_PARAMS_DELAY": float,
        "TIME_PULL": float,
        "MAX_DELAY_TIME": int,
        "MAX_RETRIEVE": int,
        "PATH_LENGTH": int,
        "DATABASE_NAME": str,
        "DATA_DIR": str,
        "EXP_PARAMS_CHECK": float,
    }

    def __init__(self, config_paths):
        self._configs = {}
        if isinstance(config_paths, str):  # 单个文件
            config_paths = [config_paths]
        for path in config_paths:
            with open(path, 'r') as infile:
                config = json.load(infile)
                self._configs.update(config)  # 合并所有配置文件

    def _cast_value(self, key, value, module=None):
        # 如果 module 是 "tor"，所有参数都转为 int
        if module == "tor":
            return int(value)
        # 否则使用 TYPE_CASTS 的定义
        return self.TYPE_CASTS.get(key, str)(value)

    def _get_params(self, module, section):
        """通用参数提取，支持模块（如 loopix、tor）和子部分（如 parametersClients）"""
        params_dict = {}
        section_data = self._configs.get(module, {}).get(section, {})
        for key, value in section_data.items():
            params_dict[key] = self._cast_value(key, value, module)
        return params_dict

    def get_loopix_config_params(self, paramsname, module="loopix"):
        params = self._get_params(module, paramsname)
        Params = namedtuple('Params', params.keys())
        return Params(**params)

    def get_tor_config_params(self, paramsname, module="tor"):
        params = self._get_params(module, paramsname)
        Params = namedtuple('Params', params.keys())
        return Params(**params)



