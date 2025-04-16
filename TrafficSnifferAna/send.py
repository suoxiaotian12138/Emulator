import os
from scapy.all import rdpcap, sendp
import time

# 选择网卡名称
iface = "Intel(R) Ethernet Connection (17) I219-LM"  # 根据你的系统情况替换

# 设置你的 pcap 文件夹路径
pcap_folder = "D:\\new\\trimed_sessioned_dataset\\google_2-ALL"

# 获取文件夹中所有 .pcap 文件（支持大小写）
pcap_files = [f for f in os.listdir(pcap_folder) if f.lower().endswith(".pcap")]

print(f"找到 {len(pcap_files)} 个 pcap 文件，开始发送...")

for pcap_file in sorted(pcap_files):
    full_path = os.path.join(pcap_folder, pcap_file)
    print(f"正在发送: {full_path}")

    try:
        packets = rdpcap(full_path)
        for pkt in packets:
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.01)  # 可调节速率
    except Exception as e:
        print(f"发送出错: {e}")

print("全部发送完成。")
