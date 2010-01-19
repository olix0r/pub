import socket

# Convenience exports
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


def IP(address):
    error = None

    for klass in (IPv4Address, IPv6Address):
        try:
            ip = klass(address)
            return ip

        except ValueError, ve:
            error = ve

    assert error is not None
    raise error



class IPAddress(object):
    addressFamily = None  # Overridden below

    def __init__(self, address):
        assert self.addressFamily
        try:
            bytes = socket.inet_pton(self.addressFamily, address)

        except socket.error:
            raise ValueError("Invalid IP address", address)

        self._bytes = bytes


    @property
    def AF(self):
        return self.addressFamily


    def __eq__(self, obj):
        equality = False
        if isinstance(obj, IPAddress) and self.AF == obj.AF:
            try:
                bytes = socket.inet_pton(obj.AF, str(obj))
            except: pass
            else:
                equality = bool(self._bytes == bytes)

        elif isinstance(obj, basestring):
            equality = bool(str(self) == obj)

        return equality


    def __hash__(self):
        return hash(self._bytes)


    def __str__(self):
        return socket.inet_ntop(self.AF, self._bytes)

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, str(self))



class IPv4Address(IPAddress):
    addressFamily = AF_INET


class IPv6Address(IPAddress):
    addressFamily = AF_INET6


