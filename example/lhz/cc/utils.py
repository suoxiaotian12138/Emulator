from scapy.all import *
from datetime import datetime

PROTO_MAP = {
    "TCP": TCP,
    "UDP": UDP,
    "RTP": RTP,
    "ICMP": ICMP
}

GLOBAL_VERBOSE_LEVEL = 1
VERBOSE = ["DEBUG", "INFO", "WARNING", "ERROR", "FATAL"]

def extract_pkt_by_protocol(org_traffic: PacketList, protocol: str):
    protocol = PROTO_MAP[protocol.upper()]
    packet_indexes = [i for i, pkt in enumerate(org_traffic) if protocol in pkt]
    extracted_pkts = PacketList([org_traffic[i] for i in packet_indexes])
    return packet_indexes, extracted_pkts

def extract_flows_by_five_tuple(org_traffic: PacketList):
    flows = defaultdict(list)
    for pkt in org_traffic:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if TCP in pkt:
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            else:
                protocol = pkt[IP].proto
                src_port = None
                dst_port = None
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            if flow_key not in flows:
                flows[flow_key] = PacketList()
            flows[flow_key].append(pkt)
    return flows

def check_protocol_header_field(protocol: str, field: str):
    protocol_header_fields = {
        "TCP": ["sport", "dport", "seq", "ack", "dataofs", "reserved", "flags", "window", "chksum", "urgptr", "options"],
        "UDP": ["sport", "dport", "len", "chksum"],
        "RTP": ["version", "padding", "extension", "csrc_count", "marker", "payload_type", "seq", "timestamp", "ssrc"]
    }
    if protocol.upper() not in protocol_header_fields:
        return False
    if field not in protocol_header_fields[protocol.upper()]:
        return False
    return True

def extract_traffic_fields(org_traffic: PacketList, pkt_indexes: list, protocol: str, field: str):
    fields = []
    if not check_protocol_header_field(protocol, field):
        raise ValueError("protocol field is not correct")
    protocol = PROTO_MAP[protocol.upper()]
    for i in pkt_indexes:
        pkt = org_traffic[i]
        f = getattr(pkt[protocol], field)
        fields.append(f)
    return fields

def extract_traffic_pkt_sizes(org_traffic: PacketList, pkt_indexes: list):
    sizes = []
    for i in pkt_indexes:
        pkt = org_traffic[i]
        size = len(bytes(pkt))
        sizes.append(size)
    return sizes

def extract_traffic_inter_packet_delays(org_traffic: PacketList, pkt_indexes: list):
    delays = []
    for i in range(1, len(pkt_indexes)):
        delay = org_traffic[pkt_indexes[i]].time - org_traffic[pkt_indexes[i - 1]].time
        delays.append(delay)
    return delays

def modify_traffic_fields(values: list, traffic: PacketList, pkt_indexes: list, protocol: str, field: str):
    if not check_protocol_header_field(protocol, field):
        raise ValueError("protocol field is not correct")
    protocol = PROTO_MAP[protocol.upper()]
    for i in range(len(pkt_indexes)):
        pkt_id = pkt_indexes[i]
        value = values[i]
        setattr(traffic[pkt_id][protocol], field, value)
    return traffic

def modify_traffic_pkt_sizes(sizes: list, traffic: PacketList, pkt_indexes: list, append_bytes: bytes = b"A"):
    # truncate or extend the packet size
    for i in range(len(pkt_indexes)):
        pkt_id = pkt_indexes[i]
        size = sizes[i]

        pkt = traffic[pkt_id]
        pkt_bytes = bytes(pkt)
        if len(pkt_bytes) < size:
            pkt_bytes += append_bytes * (size - len(pkt_bytes))
        elif len(pkt_bytes) > size:
            pkt_bytes = pkt_bytes[:size]
        else:
            pass
        pkt = pkt.__class__(pkt_bytes)
        traffic[pkt_id] = pkt
    return traffic

def modify_traffic_inter_packet_delays(traffic: PacketList, pkt_indexes: list, delays: list):
    for i in range(1, len(pkt_indexes)):
        pkt_id = pkt_indexes[i]
        last_pkt_id = pkt_indexes[i - 1]
        delay = delays[i - 1]
        traffic[pkt_id].time = traffic[last_pkt_id].time + delay
    return traffic

def verbose_print(*args, level: int = 1):
    if level >= GLOBAL_VERBOSE_LEVEL:
        msg = ' '.join([str(arg) for arg in args])
        print('[' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ']', VERBOSE[level] + ":", msg)