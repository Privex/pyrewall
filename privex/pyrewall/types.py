from enum import Enum


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
