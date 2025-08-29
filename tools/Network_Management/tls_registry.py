import ssl
import asyncio

# 全局信号量
_global_sem = asyncio.Semaphore(512)
_node_sems = {}

def get_global_sem():
    return _global_sem

def get_node_sem(node_id: str):
    if node_id not in _node_sems:
        _node_sems[node_id] = asyncio.Semaphore(128)  # 每节点限流
    return _node_sems[node_id]

# 缓存每个节点的 server_ctx
_server_ctxs = {}

def make_server_ctx(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ALL:@SECLEVEL=1")
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx

def make_client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ALL:@SECLEVEL=1")
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def register_server_ctx(node_id: str, certfile: str, keyfile: str):
    _server_ctxs[node_id] = make_server_ctx(certfile, keyfile)

def get_server_ctx(node_id: str):
    return _server_ctxs[node_id]

_client_ctx = make_client_ctx()
def get_client_ctx():
    return _client_ctx
