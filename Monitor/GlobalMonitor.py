









class GlobalMonitor:
    def log_drop(self, src, dst, reason):
        ...

    def log_delay(self, src, dst, delay):
        ...

    def log_packet(self, src, dst):
        ...

    def summary(self):
        ...