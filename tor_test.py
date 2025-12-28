import ssl
import io

# 创建一个SSLObject看是否有该方法
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

incoming = ssl.MemoryBIO()
outgoing = ssl.MemoryBIO()
ssl_obj = ctx.wrap_bio(incoming, outgoing, server_hostname='test')

print("Has export_keying_material?", hasattr(ssl_obj, 'export_keying_material'))
print("ssl_obj type:", type(ssl_obj))
print("ssl_obj methods:", [m for m in dir(ssl_obj) if 'export' in m.lower()])