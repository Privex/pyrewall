import re
from enum import Enum
from ipaddress import IPv4Network, IPv6Network, ip_network
from os.path import join
from typing import List, Union, Dict, Tuple
from privex.helpers import empty, is_true
from collections import OrderedDict
import logging

log = logging.getLogger(__name__)


def find_file(filename: str, paths: List[str]) -> str:
    """Attempt to find a file in a given list of paths"""
    for p in paths:
        fpath = join(p, filename)
        try:
            with open(fpath, 'r'):
                return fpath
        except FileNotFoundError:
            continue
    raise FileNotFoundError(f'File "{filename}" could not be found in any of the given paths.')


def valid_port(port: Union[str, int]):
    try:
        port = int(port)
        if port > 65535 or port < 1:
            raise InvalidPort
        return port
    except Exception:
        raise InvalidPort(f'Port number "{port}" is not a valid port number')


class PyreException(Exception):
    pass


class RuleSyntaxError(PyreException):
    pass


class InvalidPort(PyreException):
    pass


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


class RuleBuilder:
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


class RuleParser:
    default_action: IPT_ACTION
    action: IPT_ACTION
    rule_type: IPT_TYPE
    table: str
    v4_rules: List[str]
    v6_rules: List[str]
    rgx_ports = re.compile(r'([0-9]+,?)+')
    # protocol: str
    rule: RuleBuilder

    def __init__(self, rule_type: IPT_TYPE = IPT_TYPE.INPUT, table='filter', strict=False):
        self.table = table
        self.rule_type = rule_type
        self.default_action = IPT_ACTION.ALLOW
        self.rule = None
        self.strict = is_true(strict)
        self.has_v4, self.has_v6 = False, False
        self.reset_rule()
        # self.protocol = None

    def reset_rule(self):
        self.rule = RuleBuilder(rule_type=self.rule_type)
        self.has_v4, self.has_v6 = False, False
        return self.rule

    def handle_port(self, *args, protocol=None, **kwargs):
        protocol = self.rule.protocol if protocol is None else protocol
        args = list(args)

        for i, a in enumerate(args[0:2]):
            a = str(a)
            if a.lower() in ['tcp', 'udp']:
                args.pop(i)
                protocol = a.lower() if protocol is not False else False
                continue

        try:
            a = args[0]
        except (KeyError, IndexError):
            raise RuleSyntaxError('No ports passed to PORT rule...')

        arg_valid = RuleParser.rgx_ports.match(a)
        if len(arg_valid.groups()) == 0:
            raise RuleSyntaxError(f"Syntax error while parsing argument to PORT rule: '{a}'")

        rule = OrderedDict()
        if protocol is not False:
            protocol = 'tcp' if empty(protocol) else protocol
            self.rule.protocol = protocol

        ports = []
        _ports = a.split(',')
        # rule = '-p tcp -m multiport --dports 61220'
        for p in _ports:
            try:
                multi = ':' in p or '-' in p
                if multi:
                    splitchar = ':' if ':' in p else '-'
                    p_start, p_end = p.split(splitchar, maxsplit=2)
                    p_start, p_end = valid_port(p_start), valid_port(p_end)

                    # rule = OrderedDict(rule)
                    # rule['-m'] = 'multiport'
                    # rule['--dports'] = f'{int(p_start)}:{int(p_end)}'
                    ports += [f'{int(p_start)}:{int(p_end)}']
                    continue
                ports += [str(valid_port(p))]
                # rule = OrderedDict(rule)
                # rule['--dports'] = f'{int(p_start)}:{int(p_end)}'
            except InvalidPort as e:
                if self.strict:
                    raise RuleSyntaxError(f"(Strict Mode) An invalid port '{p}' was present in your rule.")
                log.warning('WARNING: Invalid port in rule. Ignoring port. Message: %s', str(e))
            continue

        if len(ports) == 0:
            raise RuleSyntaxError('No valid ports passed to PORT rule...')

        self.rule.ports += ports
        args.pop(0)
        return args

    def parse(self, rule: str, reset_rule=True) -> Tuple[List[str], List[str]]:
        rule = rule.strip()
        if rule[0] == '#': return [], []

        rule = list(rule.split())
        # output_rules = dict(v4=[], v6=[])

        while len(rule) > 0:
            rl = rule.pop(0)
            if rl.strip()[0] == '#':
                log.debug('Final rule word "%s" appears to be a comment. Breaking while loop.', rl)
                break
            if rl in self.rule_handlers:
                log.debug('Handler "%s" detected. Passing remaining rule to handler.', rl)
                rule = list(self.rule_handlers[rl](self, *rule))
                continue
            log.warning('WARNING: No known handler for keyword "%s". Ignoring.', rl)

        if not self.has_v4 and not self.has_v6:
            res = list(self.rule.build())
            return res, res

        res = dict(v4=[], v6=[])
        if self.has_v4:
            res['v4'] = list(self.rule.build('v4'))
        if self.has_v6:
            res['v6'] = list(self.rule.build('v6'))

        if reset_rule:
            self.reset_rule()

        return res['v4'], res['v6']

    def handle_from(self, *args, **kwargs):
        args = list(args)
        ip4, ip6 = self._parse_ips(args.pop(0))
        self.has_v4, self.has_v6 = len(ip4) > 0 or self.has_v4, len(ip6) > 0 or self.has_v6
        self.rule.add_from_cidr(*ip4, ipver='v4')
        self.rule.add_from_cidr(*ip6, ipver='v6')
        return args

    def handle_to(self, *args, **kwargs):
        args = list(args)
        ip4, ip6 = self._parse_ips(args.pop(0))
        self.has_v4, self.has_v6 = len(ip4) > 0 or self.has_v4, len(ip6) > 0 or self.has_v6
        self.rule.add_to_cidr(*ip4, ipver='v4')
        self.rule.add_to_cidr(*ip6, ipver='v6')
        return args

    def handle_if_in(self, *args, **kwargs):
        args = list(args)
        ifaces = args.pop(0)
        self.rule.add_from_iface(*ifaces.split(','))
        return args

    def handle_if_out(self, *args, **kwargs):
        args = list(args)
        ifaces = args.pop(0)
        self.rule.add_to_iface(*ifaces.split(','))
        return args

    def _parse_ips(self, ips: str):
        ips = ips.split(',')
        ips = [ip_network(ip, strict=self.strict) for ip in ips]
        ip4 = [ip for ip in ips if isinstance(ip, IPv4Network)]
        ip6 = [ip for ip in ips if isinstance(ip, IPv6Network)]
        return ip4, ip6

    def handle_allow(self, *args, **kwargs):
        self.rule.action = IPT_ACTION.ALLOW
        return args

    def handle_forward(self, *args, **kwargs):
        self.rule.action = IPT_ACTION.FORWARD
        return args

    rule_handlers = {
        'port': handle_port,
        'allow': handle_allow,
        'forward': handle_forward,
        'from': handle_from,
        'to': handle_to,
        'if-in': handle_if_in,
        'if-out': handle_if_in,
    }



"""

rule parsing idea:

RuleParser class:
    action = 'allow' / 'drop' / 'reject'
    v4_rules = []   # list of iptables v4 rules to apply
    v6_rules = []   # list of iptables v6 rules to apply

    parse(rule: str):
        rule = rule.strip()
        # this rule is a comment
        if rule[0] == '#':
            return
        
        # split by whitespace
        rule = rule.split()
        first_word = rule.pop(0)

        # do something with the first word

        while len(rule) > 0:
            # pop another word off the stack, and pass the remaining rule parts
            # to the function that deals with it

"""
