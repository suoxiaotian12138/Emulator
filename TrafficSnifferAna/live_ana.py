from scapy.all import sniff, raw, IP, TCP, get_if_list, show_interfaces
import torch
import torch.nn as nn
import numpy as np
from collections import defaultdict, deque

from scapy.packet import Raw

from train import little_pets  # 你的模型定义
import time

tags = {
    'amazon': 0,
    'baidu': 1,
    'bing': 2,
    'douban': 3,
    'facebook': 4,
    'google': 5,
    'imdb': 6,
    'instagram': 7,
    'iqiyi': 8,
    'JD': 9,
    'NeteaseMusic': 10,
    'qqmail': 11,
    'reddit': 12,
    'taobao': 13,
    'TED': 14,
    'tieba': 15,
    'twitter': 16,
    'weibo': 17,
    'youku': 18,
    'youtube': 19,
}

# 模型输入参数
chunk = 3
long = 256

# 模型路径
model_path = './dataset/model.pth.tar'

# 设备选择
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

# 初始化模型
model = little_pets(num_classes=20)  # 修改 num_classes 根据你的实际情况
model.load_state_dict(torch.load(model_path, map_location=device))
model.to(device)
model.eval()

# 流缓存：以五元组标识，每个值是一个 deque，最多保存 chunk 个包
flow_dict = defaultdict(lambda: deque(maxlen=chunk))


# 判断是否是 TCP 流的有效数据包
def is_valid_tcp(pkt):
    return TCP in pkt and IP in pkt and pkt.haslayer(Raw) and len(pkt) > 80


# 转换一个包为固定长度字节数组（前256字节，不足补0）
def packet_to_bytes(pkt):
    newa = []
    i = 1
    for byte in raw(pkt):
        newa.append(int(byte))
    newa[26: 26 + 12] = [0] * 12

    del newa[0:14]
    if len(newa) < long:
        newa.extend(0 for _ in range(long - len(newa)))
    else:
        newa = newa[0:long]
    return newa


# 将整个流转成输入张量
def flow_to_tensor(flow_packets):
    flow_in_int = []
    for pkt in flow_packets:
        newa = []
        i = 1
        for byte in raw(pkt):
            newa.append(int(byte))

        newa[26: 26 + 12] = [0] * 12
        # newa[26] = [0] * 12
        del newa[0:14]
        if len(newa) < long:
            newa.extend(0 for _ in range(long - len(newa)))
        else:
            newa = newa[0:long]
        if len(flow_in_int) < chunk:
            flow_in_int.append(newa)

    x = np.array(flow_in_int) / 255
    x = np.reshape(x, (chunk, long)).astype(np.float32)
    return torch.tensor(x, dtype=torch.float32).to(device).unsqueeze(0)  # shape (1, chunk, long)


# 流处理逻辑
def handle_packet(pkt):
    if not is_valid_tcp(pkt):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]
    flow_id = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))  # 双向统一标识
    flow_key = ("tcp", flow_id)

    flow_dict[flow_key].append(pkt)

    if len(flow_dict[flow_key]) == chunk:
        x_tensor = flow_to_tensor(flow_dict[flow_key])
        with torch.no_grad():
            output = model(x_tensor)
            pred = torch.argmax(output, dim=1).item()
            key = next((k for k, v in tags.items() if v == pred), None)
            print(f"[{time.strftime('%X')}] 流预测结果: 类别 {key}")
        flow_dict.pop(flow_key)  # 预测后删除流（也可以选择保留）


# 启动抓包
def start_sniff(interface='eth0'):
    print(f"开始监听接口 {interface} 上的 TCP 流量...")
    sniff(iface=interface, prn=handle_packet, filter="tcp", store=0)


if __name__ == '__main__':
    show_interfaces()
    AA = get_if_list()
    print(AA)
    # 查看所有网卡名
    start_sniff(interface='Intel(R) Ethernet Connection (17) I219-LM')  # 改为你的网卡名，比如 'Wi-Fi' 或 'ens33'
