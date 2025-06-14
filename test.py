
import asyncio
from examples.Tor_simplified.Tor_Client import Tor_Client
from concurrent.futures import ThreadPoolExecutor

def setup_loop():
    executor = ThreadPoolExecutor(max_workers=10)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_default_executor(executor)
    return loop

async def main():
    client = Tor_Client(name="client1", host='10.108.10.20', port=9001, model='real')
    message = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
    addr = ('httpbin.org', 80)
    hop = 3

    # 先启动监听器
    listen_task = asyncio.create_task(client.start_protocol())
    print("[Main] Listener started. Waiting 10 seconds before sending...")

    # 等待10秒后再开始发送流
    await asyncio.sleep(20)

    client_task = asyncio.create_task(client.make_stream(message=message, addr=addr, hops_count=hop))
    print("[Main] make_stream started.")

    try:
        await client_task
        await asyncio.sleep(300)
    finally:
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            print("[Main] Listener task cancelled.")

    print("[Main] Tor_Client shutdown.")



if __name__ == "__main__":
    loop = setup_loop()
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()








# # 如果仍需要从原始字节解析的功能（比如用于测试），可以保留简化版本
# def parse_cell_from_bytes(data: bytes, protocol) -> Optional['TorCell']:
#     """
#     从完整的cell字节数据解析cell对象（主要用于测试或特殊情况）
#     """
#     if not data:
#         return None
#
#     try:
#         offset = 0
#
#         # 解析header
#         header_size = struct.calcsize(protocol.header_format)
#         if len(data) < header_size:
#             return None
#
#         header = data[offset:offset + header_size]
#         circuit_id, command_num = struct.unpack(protocol.header_format, header)
#         offset += header_size
#
#         # 获取cell类型
#         cell_type = TorCommands.get_by_num(command_num)
#         if not cell_type:
#             return None
#
#         # 处理长度字段
#         if cell_type.is_var_len():
#             len_size = struct.calcsize(protocol.length_format)
#             if len(data) < offset + len_size:
#                 return None
#
#             length_bytes = data[offset:offset + len_size]
#             (payload_len,) = struct.unpack(protocol.length_format, length_bytes)
#             offset += len_size
#         else:
#             payload_len = TorCell.MAX_PAYLOAD_SIZE
#
#         # 提取payload
#         if len(data) < offset + payload_len:
#             return None
#
#         payload = data[offset:offset + payload_len]
#
#         # 构造cell对象
#         cell = protocol.deserialize(cell_type, payload, circuit_id)
#         return cell
#
#     except (struct.error, ValueError, IndexError) as e:
#         return None

