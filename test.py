import uuid
import hashlib
import time
import random




def generate_trace_id(node_name: str, counter: int) -> str:
    """
    node_name: 当前节点名称或ID
    counter: 本地递增计数（确保唯一）
    """
    raw = f"{node_name}-{counter}-{time.time_ns()}-{random.randint(0, 1 << 32)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]  # 12位16进制




id1 = generate_trace_id("client1",1)
id2 = generate_trace_id("client2",1)
id3 = generate_trace_id("client1",2)

print(id1)
print(id2)
print(id3)
