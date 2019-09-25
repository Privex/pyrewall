from enum import Enum
from ipaddress import IPv4Network, IPv6Network
from typing import TypeVar, List


class IPT_ACTION(Enum):
    ALLOW = '-j ACCEPT'
    REJECT = '-j REJECT'
    DROP = '-j DROP'
    CUSTOM = '#CUSTOM#'


class IPT_TYPE(Enum):
    INPUT = '-A INPUT'
    OUTPUT = '-A OUTPUT'
    FORWARD = '-A FORWARD'
    POSTROUTING = '-A POSTROUTING'
    PREROUTING = '-A PREROUTING'


T = TypeVar('T', str, list, dict, IPv4Network, IPv6Network)


class IPVersionList(object):
    """
    Stores generic lists sorted by IP version (v4 / v6).
    Allows access via attributes e.g. ``x.v4`` and subscripting e.g ``x['v6']``

        >>> x = IPVersionList(v4=['hello'], v6=['world'])
        >>> x.v4.append('world')
        >>> x['v6'] = ['hello'] + x['v6']


    """
    v4: List[T]
    v6: List[T]

    def __init__(self, v4: List[T] = None, v6: List[T] = None):
        self.v4 = [] if not v4 else v4
        self.v6 = [] if not v6 else v6

    def get(self, attr: str) -> List[T]:
        return getattr(self, attr)

    @property
    def ipv4(self) -> List[T]: return self.v4

    @property
    def ipv6(self) -> List[T]: return self.v6

    def __getitem__(self, item) -> List[T]:
        return getattr(self, item)

    def __setitem__(self, key, value):
        # super(IPVersionList, self).__setattr__(key, value)
        setattr(self, key, value)

    def __contains__(self, item):
        return item in ['v4', 'v6', 'ipv4', 'ipv6']

    def __iter__(self):
        """Allow casting into dict()"""
        for k, v in dict(v4=self.v4, v6=self.v6).items():
            yield (k, v,)

    def __repr__(self): return str(dict(self))

    def __str__(self): return self.__repr__()
