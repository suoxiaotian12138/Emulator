# 统一保存“是否开启注入 + 映射 + 模型”
from __future__ import annotations
from typing import Optional
from .geo_delay_injector import MappingCache, GeoDelayModel

_ENABLED: bool = False
_MAPPING: Optional[MappingCache] = None
_MODEL: Optional[GeoDelayModel] = None
_MODE: str = "burst"

def configure(*, enabled: bool, mapping: Optional[MappingCache], model: Optional[GeoDelayModel], delay_mode: str = "burst") -> None:
    global _ENABLED, _MAPPING, _MODEL, _MODE
    _ENABLED = bool(enabled)
    _MAPPING = mapping
    _MODEL = model
    _MODE = delay_mode

def get_args(sim_ip: Optional[str]):
    """
    给 Tor_Socket 的构造/拨号直接解包使用：
      sock = Tor_Socket(..., **get_args(sim_ip=self.sim_ip))
      或
      Tor_Socket.dial(..., **get_args(sim_ip=self.sim_ip))
    """
    return dict(
        enable_delay=_ENABLED,
        sim_ip=sim_ip,
        delay_mapping=_MAPPING,
        delay_model=_MODEL,
        delay_mode=_MODE,
    )
