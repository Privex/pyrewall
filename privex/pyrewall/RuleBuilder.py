from ipaddress import IPv4Network, IPv6Network
from typing import List, Dict, Union, Optional, Tuple
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
    ICMP_ALIASES = ['icmp', 'icmp4', 'icmp6', 'icmpv4', 'icmpv6', 'ipv6-icmp']

    default_action: IPT_ACTION = IPT_ACTION.ALLOW
    action: IPT_ACTION
    custom_action: str
    rule_type: str
    extra_types: List[str]

    protocol: str
    extra_protocols: List[str]
    ports: List[str]
    sports: List[str]
    match_rules: List[str]

    from_cidr: Dict[str, List[Union[IPv4Network, IPv6Network]]]
    to_cidr: Dict[str, List[Union[IPv4Network, IPv6Network]]]
    from_iface: List[str]
    to_iface: List[str]

    icmp_types: Dict[str, List[int]]

    rule_comment: Dict[str, Optional[str]]

    def __init__(self, rule_type: str = IPT_TYPE.INPUT.value, **kwargs):
        self.rule_type = str(rule_type)
        self.action, self.protocol, self.from_cidr, self.to_cidr = None, None, dict(v4=[], v6=[]), dict(v4=[], v6=[])
        self.from_iface, self.to_iface = [], []
        self.ports, self.sports, self.extra_protocols, self.match_rules, self.extra_types = [], [], [], [], []
        self.icmp_types = dict(v4=[], v6=[])

        self.rule_comment = dict(v4=None, v6=None)

        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)

    def _build(self, protocol=None, from_cidr=None, to_cidr=None, from_iface=None, to_iface=None,
               ipver='v4', rule_type: str = None, **kwargs):

        rule = ''
        action = self.default_action if self.action is None else self.action
        rule += self.rule_type if empty(rule_type) else f'-A {rule_type}'
        protocol = self.protocol if empty(protocol) else protocol

        s_from = self.from_cidr[ipver]
        s_to = self.to_cidr[ipver]
        from_cidr = s_from[0] if empty(from_cidr) and len(s_from) > 0 else from_cidr
        to_cidr = s_to[0] if empty(to_cidr) and len(s_to) > 0 else to_cidr

        from_iface = self.from_iface[0] if empty(from_iface) and len(self.from_iface) > 0 else from_iface
        to_iface = self.to_iface[0] if empty(to_iface) and len(self.to_iface) > 0 else to_iface

        if not empty(protocol): 
            if protocol in self.ICMP_ALIASES:
                protocol = 'icmp' if ipver == 'v4' else 'ipv6-icmp'

            rule += f' -p {protocol}'

        icmp_types: Optional[int] = self.icmp_types[ipver]
        icmp_type: Optional[int] = kwargs.get('icmp_type', None if empty(icmp_types,itr=True) else icmp_types[0])
        if protocol in self.ICMP_ALIASES and not empty(icmp_type):
            rule += f' --icmp-type {icmp_type}' if ipver == 'v4' else f' --icmpv6-type {icmp_type}'

        rule += self.build_ports()
        rule += self.build_sports()

        for m in self.match_rules:
            rule += f' {m}'


        if not empty(from_cidr):  rule += f' -s {str(from_cidr)}'
        if not empty(to_cidr):    rule += f' -d {str(to_cidr)}'
        if not empty(from_iface): rule += f' -i {str(from_iface)}'
        if not empty(to_iface):   rule += f' -o {str(to_iface)}'

        rule += f' -j {self.custom_action}' if action is IPT_ACTION.CUSTOM else f' {action.value}'
        return rule

    def build(self, ipver='v4'):
        if self.protocol in ['icmpv4', 'icmp4'] and ipver != 'v4':
            return []
        if self.protocol in ['icmpv6', 'icmp6', 'ipv6-icmp'] and ipver != 'v6':
            return []
        if self.protocol in ['comment', 'rem', 'rem4', 'rem6']:
            if self.rule_comment.get(ipver) is not None:
                return [f"# {self.rule_comment.get(ipver)}"]
            return []
        
        rules = [self._build(ipver=ipver)]
        if self.rule_comment.get(ipver) is not None:
            rules = [f"# {self.rule_comment.get(ipver)}"] + rules
        extra_rule_args = []

        def add_arg(pos, **data):
            if len(extra_rule_args) > pos:
                extra_rule_args[pos] = {**extra_rule_args[pos], **data}
                return
            extra_rule_args.append(data)

        if len(self.from_cidr[ipver]) > 1:
            for i, p in enumerate(self.from_cidr[ipver][1:]):
                add_arg(i, from_cidr=p)

        if len(self.to_cidr[ipver]) > 1:
            for i, p in enumerate(self.to_cidr[ipver][1:]):
                add_arg(i, to_cidr=p)

        if len(self.from_iface) > 1:
            for i, p in enumerate(self.from_iface[1:]):
                add_arg(i, from_iface=p)
        
        if len(self.icmp_types[ipver]) > 1:
            for i, p in enumerate(self.icmp_types[ipver][1:]):
                add_arg(i, icmp_type=p)

        if len(self.to_iface) > 1:
            for i, p in enumerate(self.to_iface[1:]):
                add_arg(i, to_iface=p)

        # To avoid the issue of the list growing as we loop it, we clone the current extra rules
        orig_extra_args = list(extra_rule_args)
        for p in self.extra_protocols:
            # For each extra protocol, we duplicate the base rule with the different protocol
            extra_rule_args.append({'protocol': p})
            # Then we do the same for each existing extra rule argument
            for r in orig_extra_args:
                extra_rule_args.append({**r, 'protocol': p})

        # We clone the list again so the for loop is aware of any extra protocols
        orig_extra_args = list(extra_rule_args)
        for p in self.extra_types:
            # Just like with the extra protocols, we duplicate the base rule with the extra type/chain
            # as well as repeating this for each extra rule
            extra_rule_args.append({'rule_type': p})
            for i, r in enumerate(orig_extra_args):
                extra_rule_args.append({**r, 'rule_type': p})

        # Finally, we loop over all the extra rules and generate their IPTables line with _build()
        for a in extra_rule_args:
            rules.append(self._build(**a, ipver=ipver))

        return rules

    def add_from_cidr(self, *args, ipver='v4'): self.from_cidr[ipver] += args

    def add_to_cidr(self, *args, ipver='v4'): self.to_cidr[ipver] += args

    def add_from_iface(self, *args): self.from_iface += args

    def add_to_iface(self, *args): self.to_iface += args

    def add_rule_type(self, *args): self.extra_types += args

    def add_icmp_types(self, *args, ipver='v4'): self.icmp_types[ipver] += args

    def set_comment(self, *args, ipver='v4'): self.rule_comment[ipver] = ' '.join(args)

    def _parse_ports(self, ports, direction='d'):
        if not empty(ports, itr=True):
            if len(ports) == 1 and ':' not in ports[0]:
                return f' --{direction}port {ports[0]}'
            portstr = ','.join(ports)
            return f' -m multiport --{direction}ports {portstr}'
        return ''

    def build_ports(self):
        return self._parse_ports(ports=self.ports, direction='d')

    def build_sports(self):
        return self._parse_ports(ports=self.sports, direction='s')

