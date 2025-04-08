import socket

def send_udp_packet(host, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (host, port))
    sock.close()

send_udp_packet("127.0.0.1", 9994, "Test message")
