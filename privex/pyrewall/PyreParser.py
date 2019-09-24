import logging
from typing import List
from privex.pyrewall.RuleParser import RuleParser
from privex.pyrewall.core import find_file
from privex.pyrewall import conf

log = logging.getLogger(__name__)


EXTENSION_TYPES = conf.EXTENSION_TYPES


class PyreParser:
    """
    PyreParser - The highest level parser class - directly parses ``.pyre`` files and generates iptables compatible
    configuration lines.

    The class is a layer above :class:`.RuleParser`, PyreParser handles special "control" directives such as
    ``@import``, ``@chain`` and ``@table`` and generates entire iptables configurations, not just single lines.

    Basic usage:

        >>> from privex.pyrewall import PyreParser, find_file, conf
        >>> r = PyreParser()
        >>> r.parse_file(find_file('test.pyre', paths=conf.SEARCH_DIRS, extensions=conf.SEARCH_EXTENSIONS))

    """
    DEFAULT_CHAINS = conf.DEFAULT_CHAINS

    def __init__(self, table='filter', chains: dict = None, **rp_args):
        self.table = table
        self.chains = dict(self.DEFAULT_CHAINS[self.table]) if not chains else chains
        self.cache = dict(v4=[], v6=[])
        self.output = dict(v4=[], v6=[])
        self.committed = False
        self.rp = RuleParser(**rp_args)

    def parse_lines(self, lines: List[str]):
        for _line in lines:
            self._parse(_line)
        log.debug('Finished parsing lines. Committing.')
        self.commit()
        return self.output['v4'], self.output['v6']

    def import_file(self, *args):

        # _path, ftype = None, 'pyre'
        if len(args) == 1:
            _path = args[0]
            ext = '.' + _path.split('.')[-1]
            ftype = EXTENSION_TYPES[ext] if ext in EXTENSION_TYPES else 'pyre'
        elif len(args) >= 2:
            _path = args[1]
            ftype = args[0] if args[0] in EXTENSION_TYPES.values() else 'pyre'
        else:
            raise AttributeError('import_file expects at least one argument')

        path = find_file(filename=_path, paths=conf.SEARCH_DIRS, extensions=conf.SEARCH_EXTENSIONS)
        log.info('Importing %s file at %s ...', ftype, path)
        with open(path, 'r') as fh:
            lines = fh.readlines()
            for l in lines:
                if ftype == 'pyre': self._parse(l)
                if ftype == 'ip4': self.cache['v4'] += [l.strip()]
                if ftype == 'ip6': self.cache['v6'] += [l.strip()]
        log.info('Successfully imported "%s" ...', _path)

    def _parse(self, line: str):
        sline = line.split()
        if len(sline) == 0 or sline[0].strip()[0] == '#':
            log.debug('Skipping empty line')
            return
        if sline[0] in self.control_handlers:
            log.debug('Detected control keyword "%s" - passing to handler', sline[0])
            self.control_handlers[sline[0]](self, *sline[1:])
            return
        log.debug('Passing line starting with "%s" to RuleParser', sline[0])
        v4_rules, v6_rules = self.rp.parse(line)
        self.cache['v4'] += v4_rules
        self.cache['v6'] += v6_rules

    def parse_file(self, path: str):
        with open(path, 'r') as fh:
            lines = fh.readlines()
            return self.parse_lines(lines=lines)

    def _commit(self, ipver='v4'):
        log.debug('Committing IP%s cache to output', ipver)
        header = [f'*{self.table}']
        for cname, cdata in self.chains.items():
            header += [f':{cname} {cdata[0]} {cdata[1]}']
        merged = header + self.cache[ipver] + ['COMMIT', f'### End of table {self.table} ###']
        self.output[ipver] += merged
        self.cache[ipver] = []

    def commit(self, *args):

        if len(self.cache['v4']) > 0:
            self._commit('v4')

        if len(self.cache['v6']) > 0:
            self._commit('v6')

        self.chains = self.DEFAULT_CHAINS.get(self.table, {})

    def set_table(self, *args):
        table = args[0]
        log.debug('Setting table to "%s"', table)
        if not self.committed:
            self.commit()
        self.table = self.rp.table = table
        self.chains = self.rp.chains = dict(self.DEFAULT_CHAINS.get(self.table, {}))

    def set_chain(self, *args):
        if len(args) == 0:
            raise AttributeError('set_chain expects at least one argument')
        chain = args[0]
        policy = 'ACCEPT' if len(args) < 2 else args[1]
        packets = '[0:0]' if len(args) < 3 else args[2]
        log.debug('Setting chain %s to policy %s with packet counts "%s"', chain, policy, packets)
        self.chains[chain] = self.rp.chains[chain] = [policy, packets]

    control_handlers = {
        '@table': set_table,
        '@chain': set_chain,
        '@import': import_file,
    }
