from torpy.crypto_common import  b64decode





class Router:
    def __init__(self, nickname, fingerprint, ip, or_port, dir_port,
                 flags, version=None, digest=None, **kwargs):
        self._nickname = nickname
        if type(fingerprint) is not bytes:
            fingerprint = b64decode(fingerprint)
        self._fingerprint = fingerprint
        self._digest = b64decode(digest) if digest else None
        self._ip = ip
        self._or_port = or_port
        self._dir_port = dir_port
        self._version = version
        self._flags = flags

        self._consensus = None
        self._service_key = None

    @property
    def nickname(self):
        return self._nickname

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def ip(self):
        return self._ip

    @property
    def or_port(self):
        return self._or_port

    @property
    def dir_port(self):
        return self._dir_port

    @property
    def flags(self):
        return self._flags

    @cached_property
    def descriptor(self):
        logger.info('Getting descriptor for %s...', self)
        return self._consensus.get_descriptor(self._fingerprint)

    @property
    def service_key(self):
        return self._service_key

    @service_key.setter
    def service_key(self, value):
        self._service_key = value

    def __str__(self):
        """Get router string representation."""
        s = f'{self._ip}:{self._or_port}'
        comm = '; '.join(filter(None, [self._nickname, self._version]))
        if RouterFlags.Authority in self._flags:
            s += ' authority'
        if comm:
            s += f' ({comm})'
        return s

