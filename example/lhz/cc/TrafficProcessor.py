from scapy.all import *
from scapy.layers.l2 import Ether


class TrafficProcessor:
    _PROTO_MAP = {
        "TCP": TCP,
        "UDP": UDP,
        "RTP": RTP,
        "ICMP": ICMP
    }
    def __init__(self, pcap_filepath: str):
        self._org_traffic_filepath = pcap_filepath
        self._org_traffic = rdpcap(pcap_filepath)
        self._traffic_flows = {}
        self._traffic_flows_index = {}
        self._filtered_flows = {}
        self._filtered_flows_index = {}
        self._output_traffic = self._org_traffic

    def get_traffic_flows(self, five_tuple: tuple = None):
        if five_tuple != None:
            return self._traffic_flows[five_tuple]
        else:
            return self._traffic_flows

    def get_traffic_flows_tuple(self):
        return list(self._filtered_flows.keys())

    def get_traffic_flows_index(self, five_tuple: tuple = None):
        if five_tuple != None:
            return self._traffic_flows_index[five_tuple]
        else:
            return self._traffic_flows_index

    def get_output_traffic(self):
        return self._output_traffic
    def save_output_traffic(self, save_filepath: str):
        wrpcap(save_filepath, self._output_traffic)

    def extract_pkt_by_protocol(self, protocol: str):
        protocol = self._PROTO_MAP[protocol.upper()]
        packet_indexes = [i for i, pkt in enumerate(self._org_traffic) if protocol in pkt]
        extracted_pkts = PacketList([self._org_traffic[i] for i in packet_indexes])
        return packet_indexes, extracted_pkts

    def separate_flows_by_five_tuple(self):
        flows = defaultdict(list)
        flows_index = defaultdict(list)
        for i in range(len(self._org_traffic)):
            pkt = self._org_traffic[i]
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                if TCP in pkt:
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    if RTP in pkt:
                        protocol = "RTP"
                    else:
                        protocol = "UDP"
                else:
                    protocol = pkt[IP].proto
                    src_port = None
                    dst_port = None
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                if flow_key not in flows:
                    flows[flow_key] = PacketList()
                if flow_key not in flows_index:
                    flows_index[flow_key] = []
                flows[flow_key].append(pkt)
                flows_index[flow_key].append(i)

        self._traffic_flows = flows
        self._traffic_flows_index = flows_index


    def filter_flows(self, min_length: int, filter_protocol: str):
        filtered_flows = {}
        filtered_flows_index = {}
        for key, pkts in self._traffic_flows.items():
            if min_length != None and len(pkts) < min_length:
                continue
            if filter_protocol != None and key[4] != filter_protocol:
                continue
            filtered_flows[key] = pkts
            filtered_flows_index[key] = self._traffic_flows_index[key]
        self._filtered_flows = filtered_flows
        self._filtered_flows_index = filtered_flows_index


    def _check_protocol_header_field(self, protocol: str, field: str):
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

    def extract_traffic_fields(self, traffic: PacketList, protocol: str, field: str):
        fields = []
        if not self._check_protocol_header_field(protocol, field):
            raise ValueError("protocol field is not correct")
        protocol = self._PROTO_MAP[protocol.upper()]
        for i in range(len(traffic)):
            pkt = traffic[i]
            f = getattr(pkt[protocol], field)
            fields.append(f)
        return fields

    def extract_traffic_pkt_sizes(self, traffic: PacketList):
        sizes = []
        for i in range(len(traffic)):
            pkt = traffic[i]
            size = len(bytes(pkt))
            sizes.append(size)
        return sizes

    def extract_traffic_inter_packet_delays(self, traffic: PacketList):
        delays = []
        for i in range(1, len(traffic)):
            delay = traffic[i].time - traffic[i - 1].time
            delays.append(float(delay))
        delays.append(delays[-1]) # to make the length same as the traffic
        return delays

    def extract_traffic_payloads(self, traffic: PacketList):
        payloads = []
        for i in range(len(traffic)):
            pkt = traffic[i]
            if Raw in pkt:
                payloads.append(bytes(pkt[Raw]))
            else:
                payloads.append(None)
        return payloads

    def modify_traffic_fields(self, values: list, pkt_indexes: list, protocol: str, field: str):
        if not self._check_protocol_header_field(protocol, field):
            raise ValueError("protocol field is not correct")
        protocol = self._PROTO_MAP[protocol.upper()]
        index_limit = min(len(pkt_indexes), len(values))
        for i in range(index_limit):
            pkt_id = pkt_indexes[i]
            value = values[i]
            setattr(self._output_traffic[pkt_id][protocol], field, value)

    def _parse_packet(self, pkt_bytes):
        try:
            return Ether(pkt_bytes)
        except Exception:
            try:
                return IP(pkt_bytes)
            except Exception:
                return Raw(pkt_bytes)

    def modify_traffic_pkt_sizes(self, sizes: list, pkt_indexes: list, append_bytes: bytes = b"A"):
        # truncate or extend the packet size
        modified_pkts = PacketList()
        size_index = 0
        for i in range(len(self._org_traffic)):
            if i in pkt_indexes and size_index < len(sizes): # embedded packets
                pkt = self._output_traffic[i]
                size = int(sizes[size_index])
                size_index += 1
                if len(pkt) <= size:
                    padding_length = size - len(pkt)
                    pkt = pkt / Raw(append_bytes * padding_length)
                else:
                    pkt_time = pkt.time
                    pkt = self._parse_packet(bytes(pkt)[:size])
                    pkt.time = pkt_time
                modified_pkts.append(pkt)
            else:
                modified_pkts.append(self._output_traffic[i])

        self._output_traffic = modified_pkts


    def modify_traffic_inter_packet_delays(self, delays: list, pkt_indexes: list):
        min_length = min(len(delays), len(pkt_indexes))
        for i in range(1, min_length):
            pkt_id = pkt_indexes[i]
            last_pkt_id = pkt_indexes[i - 1]
            delay = delays[i - 1]
            self._output_traffic[pkt_id].time = self._output_traffic[last_pkt_id].time + delay



