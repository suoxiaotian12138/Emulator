# 注册器：node_id -> { enable, local_sim_ip, mapping, model }
# 让 Tor_Socket 在 setup_socket() 时能自动找到注入参数。
from __future__ import annotations
from typing import Optional, Dict

_REGISTRY: Dict[str, dict] = {}
_DEFAULT: Optional[dict] = None

def register_delay_env(
    node_id: str,
    *,
    enable: bool,
    local_sim_ip: str,
    mapping,
    model,
) -> None:
    _REGISTRY[node_id] = {
        "enable": bool(enable),
        "local_sim_ip": local_sim_ip,
        "mapping": mapping,
        "model": model,
    }

def unregister_delay_env(node_id: str) -> None:
    _REGISTRY.pop(node_id, None)

def clear_all() -> None:
    _REGISTRY.clear()

def set_default_env(*, enable: bool, local_sim_ip: str, mapping, model) -> None:
    global _DEFAULT
    _DEFAULT = {
        "enable": bool(enable),
        "local_sim_ip": local_sim_ip,
        "mapping": mapping,
        "model": model,
    }

def clear_default_env() -> None:
    global _DEFAULT
    _DEFAULT = None

def get_delay_cfg_for(node_id: Optional[str]) -> Optional[dict]:
    if node_id and node_id in _REGISTRY:
        return _REGISTRY[node_id]
    return _DEFAULT
