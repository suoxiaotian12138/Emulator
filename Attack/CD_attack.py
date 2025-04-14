import types
import random
import threading

class AttackerHook:
    def __init__(self, drop_list=None, delay_range=(0, 0)):
        """
        drop_list: [(addr, drop_rate)]
            addr = ('ip', port)
            drop_rate = float 0.0 ~ 1.0
        """
        self.drop_dict = dict(drop_list or [])
        self.delay_range = delay_range

    def inject(self, protocol):
        original_recv = protocol.datagramReceived
        original_class_send = protocol.sender.__class__.send

        def should_drop(addr):
            return addr in self.drop_dict and random.random() < self.drop_dict[addr]

        # Hook recv
        def hooked_recv(this, data, addr):

            if should_drop(addr):
                print(f"[Attack-Recv] DROP from {addr}")
                return
            delay = random.uniform(*self.delay_range)
            print(f"[Attack-Recv] DELAY {delay:.3f}s from {addr}")
            threading.Timer(delay, original_recv, args=(data, addr)).start()

        # Hook send - 修改这部分
        def hooked_send(this, packet, host, port, resolved_adrs=None):
            target = (host, port)
            if should_drop(target):
                print(f"[Attack-Send] DROP to {target}")
                return None
            return original_class_send(this, packet, host, port, resolved_adrs)

        protocol.datagramReceived = types.MethodType(hooked_recv, protocol)
        protocol.sender.__class__.send = hooked_send

