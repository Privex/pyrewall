from ipaddress import IPv4Network, IPv6Network
from typing import List, Dict, Union
from privex.helpers import empty
from privex.pyrewall.types import IPT_TYPE, IPT_ACTION
import logging

log = logging.getLogger(__name__)


class RuleBuilder:
    """
    RuleBuilder - A class for constructing iptables rules, with auto generation of related rules

    Basic usage:

        >>> from ipaddress import ip_network
        >>> r = RuleBuilder()
        >>> r.ports += ['80', '443']
        >>> r.add_from_cidr(ip_network('192.168.0.0/16'))
        >>> r.add_from_cidr(ip_network('2a07:e00:abc:def::/64'), ipver='v6')
        >>> r.build()
        ['-A INPUT -m multiport --dports 80,443 -s 192.168.0.0/16 -j ACCEPT']
        >>> r.build('v6')
        ['-A INPUT -m multiport --dports 80,443 -s 2a07:e00:abc:def::/64 -j ACCEPT']



    """
    default_action: IPT_ACTION = IPT_ACTION.ALLOW
    action: IPT_ACTION
    custom_action: str
    rule_type: IPT_TYPE

    protocol: str
    extra_protocols: List[str]
    ports: List[str]
    match_rules: List[str]

    from_cidr: Dict[str, List[Union[IPv4Network, IPv6Network]]]
    to_cidr: Dict[str, List[Union[IPv4Network, IPv6Network]]]
    from_iface: List[str]
    to_iface: List[str]

    def __init__(self, rule_type: IPT_TYPE = IPT_TYPE.INPUT, **kwargs):
        self.rule_type = rule_type
        self.action, self.protocol, self.from_cidr, self.to_cidr = None, None, dict(v4=[], v6=[]), dict(v4=[], v6=[])
        self.from_iface, self.to_iface = [], []
        self.ports, self.extra_protocols, self.match_rules = [], [], []

        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)

    def _build(self, protocol=None, from_cidr=None, to_cidr=None, from_iface=None, to_iface=None, ipver='v4'):
        rule = ''
        action = self.default_action if self.action is None else self.action
        rule += self.rule_type.value
        protocol = self.protocol if empty(protocol) else protocol

        s_from = self.from_cidr[ipver]
        s_to = self.to_cidr[ipver]
        from_cidr = s_from[0] if empty(from_cidr) and len(s_from) > 0 else from_cidr
        to_cidr = s_to[0] if empty(to_cidr) and len(s_to) > 0 else to_cidr

        from_iface = self.from_iface[0] if empty(from_iface) and len(self.from_iface) > 0 else from_iface
        to_iface = self.to_iface[0] if empty(to_iface) and len(self.to_iface) > 0 else to_iface

        if not empty(protocol): rule += f' -p {protocol}'

        rule += self.build_ports()

        for m in self.match_rules:
            rule += f' {m}'

        if not empty(from_cidr):  rule += f' -s {str(from_cidr)}'
        if not empty(to_cidr):    rule += f' -d {str(to_cidr)}'
        if not empty(from_iface): rule += f' -i {str(from_iface)}'
        if not empty(to_iface):   rule += f' -o {str(to_iface)}'

        rule += f' -j {self.custom_action}' if action is IPT_ACTION.CUSTOM else f' {action.value}'
        return rule

    def build(self, ipver='v4'):

        rules = [self._build(ipver=ipver)]
        extra_rule_args = []

        def add_arg(i, **data):
            if len(extra_rule_args) > i:
                extra_rule_args[i] = {**extra_rule_args[i], **data}
                return
            extra_rule_args.append(data)

        if not empty(self.extra_protocols, itr=True):
            for i, p in enumerate(self.extra_protocols):
                add_arg(i, protocol=p)

        if len(self.from_cidr[ipver]) > 1:
            for i, p in enumerate(self.from_cidr[ipver][1:]):
                add_arg(i, from_cidr=p)

        if len(self.to_cidr[ipver]) > 1:
            for i, p in enumerate(self.to_cidr[ipver][1:]):
                add_arg(i, to_cidr=p)

        if len(self.from_iface) > 1:
            for i, p in enumerate(self.from_iface[1:]):
                add_arg(i, from_iface=p)

        if len(self.to_iface) > 1:
            for i, p in enumerate(self.to_iface[1:]):
                add_arg(i, to_iface=p)

        for a in extra_rule_args:
            rules.append(self._build(**a))

        # if not empty(self.extra_protocols, itr=True):
        # rules.append(self._build(protocol=p))

        return rules

    def add_from_cidr(self, *args, ipver='v4'): self.from_cidr[ipver] += args
    def add_to_cidr(self, *args, ipver='v4'): self.to_cidr[ipver] += args
    def add_from_iface(self, *args): self.from_iface += args
    def add_to_iface(self, *args): self.to_iface += args

    def build_ports(self):
        ports = self.ports
        if not empty(self.ports, itr=True):
            if len(ports) == 1 and ':' not in ports[0]:
                return f' --dport {ports[0]}'
            portstr = ','.join(ports)
            return f' -m multiport --dports {portstr}'
        return ''
