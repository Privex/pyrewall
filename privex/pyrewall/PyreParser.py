import logging
from typing import List, Tuple, Dict
from privex.pyrewall.RuleParser import RuleParser
from privex.pyrewall.core import find_file
from privex.pyrewall import conf
from privex.pyrewall.exceptions import UnknownKeyword
from privex.pyrewall.types import IPVersionList

log = logging.getLogger(__name__)


EXTENSION_TYPES = conf.EXTENSION_TYPES


class PyreParser:
    """
    PyreParser - The highest level parser class - directly parses ``.pyre`` files and generates iptables compatible
    configuration lines.

    The class is a layer above :class:`.RuleParser`, PyreParser handles special "control" directives such as
    ``@import``, ``@chain`` and ``@table`` and generates entire iptables configurations, not just single lines.

    **Basic usage**

    Import required classes/functions

    >>> from privex.pyrewall import PyreParser, find_file, conf

    Get the absolute path for your Pyre rules file, initialise PyreParser, and use :py:meth:`.parse_file` to
    load the file and parse the Pyre rules.

    >>> my_config = find_file('test.pyre')   # Get abs path for the ``.pyre`` file in search dirs using find_file
    >>> r = PyreParser()
    >>> v4_rules, v6_rules = r.parse_file(path=my_config)

    Loop over the IPv4 and IPv6 rules and output them in your preferred format.

    >>> for r in v4_rules:
    ...     print(r)
    >>> for r in v6_rules:
    ...     print(r)


    """

    table: str
    """The current IPTables table being used. Default: ``filter``"""
    chains: Dict[str, List[str]]
    """A dictionary mapping chain names such as ``INPUT`` to a list of arguments, e.g. ``['ACCEPT', '[0:0]']`` """
    cache: IPVersionList
    """Contains ``List[str]``'s of the currently generated iptables rules per IP version e.g. ``self.cache.v4`` """
    output: IPVersionList
    """Contains ``List[str]``'s of the final generated iptables rules per IP version e.g. ``self.output.v4`` """
    committed: bool
    rp: RuleParser
    strict: bool = False
    DEFAULT_CHAINS: Dict[str, dict] = conf.DEFAULT_CHAINS
    """Alias for :py:attr:`privex.pyrewall.conf.DEFAULT_CHAINS` """

    def __init__(self, table='filter', chains: dict = None, **rp_args):
        """
        PyreParser - The highest level parser class - directly parses ``.pyre`` files and generates iptables compatible
        configuration lines.

        :param str   table: The default table to use if not specified in the rules file, e.g. ``filter`` or ``nat``
        :param dict chains: Optionally override the default chains used. Defaults to :py:attr:`.DEFAULT_CHAINS`
        :param     rp_args:
        """
        self.table = table
        self.chains = dict(self.DEFAULT_CHAINS[self.table]) if not chains else chains
        self.cache = IPVersionList(v4=[], v6=[])
        self.output = IPVersionList(v4=[], v6=[])
        self.committed = False
        if 'strict' in rp_args: self.strict = rp_args['strict']
        self.rp = RuleParser(**rp_args)

    def parse_lines(self, lines: List[str]) -> Tuple[List[str], List[str]]:
        """
        Takes a ``List[str]`` of Pyre rules, and parses them into a list of IPv4 / IPv6 iptables-restore rules.

        Outputs the resulting iptables-restore rules as a tuple of ``List[str]`` - in the format:

        ``(v4_rules: List[str], v6_rules: List[str],)``


        Basic usage:

            >>> lines = ['allow from 1.2.3.4/16', 'allow from 2a07:e00:abc::/48']
            >>> v4_rules, v6_rules = PyreParser().parse_lines(lines=lines)
            >>> print(v4_rules)
            ['*filter', ':INPUT ACCEPT [0:0]', ...]
            >>> print(v6_rules)
            ['*filter', ':INPUT ACCEPT [0:0]', ...]


        :param List[str] lines: A ``List[str]`` of Pyre rules to parse
        :return tuple rules: ``(v4_rules, v6_rules,)`` Each are iptables-restore compatible rules, as a ``List[str]``
        """
        for _line in lines:
            self._parse(_line)
        log.debug('Finished parsing lines. Committing.')
        self.commit()
        return self.output.v4, self.output.v6

    def _parse(self, line: str):
        """
        Parses an individual Pyre rule (``allow from x.x.x.x``) or control directive (``@table filter``) and fires
        off the appropriate handling method required.

        Doesn't do much by itself, Pyre rule's are simply passed to :py:meth:`RuleParser.parse`, while control
        directives such as ``@table [name]`` are forwarded to the appropriate control handler defined in
        :py:attr:`.control_handlers`

        **NOTE:** This method does NOT return anything. For rendering Pyre configuration into iptables rules,
        use a higher level method such as :py:meth:`.parse_lines` (takes a list of string lines), or
        :py:meth:`.parse_file` (takes an absolute path to a ``.pyre`` file and parses it directly).

        :param str line: An individual Pyre rule / control directive, e.g. ``allow from x.x.x.x`` or ``@table filter``
        """
        sline = line.split()
        if len(sline) == 0 or sline[0].strip()[0] == '#':
            log.debug('Skipping empty line')
            return [], []
        if sline[0] in self.control_handlers:
            log.debug('Detected control keyword "%s" - passing to handler', sline[0])
            self.control_handlers[sline[0]](self, *sline[1:])
            return [], []
        log.debug('Passing line starting with "%s" to RuleParser', sline[0])
        v4_rules, v6_rules = self.rp.parse(line)
        if v4_rules is None or v6_rules is None:
            if self.strict:
                raise UnknownKeyword('(strict mode) Unknown keyword detected in pyre line...')
            return None, None

        self.cache.v4 += v4_rules
        self.cache.v6 += v6_rules

        return v4_rules, v6_rules

    def parse_file(self, path: str) -> Tuple[List[str], List[str]]:
        """
        Parse a given ``.pyre`` file (absolute path!) into IPTables rules.

        Returns the IPTables rules as a tuple containing two ``List[str]``s - the first containing the IPv4 rules,
        and the second containing the IPv6 rules (or an empty list if there weren't any).

            >>> v4_rules, v6_rules = PyreParser().parse_file('/etc/pyre/test.pyre')
            >>> print(v4_rules)
            ['*filter', ':INPUT DROP [0:0]', ...]
            >>> print(v6_rules)
            ['*filter', ':INPUT DROP [0:0]', ...]

        :param str path: The absolute path to the Pyre file, e.g. ``/etc/pyre/test.pyre``
        :return tuple rules: ``(v4_rules, v6_rules,)`` Each are iptables-restore compatible rules, as a ``List[str]``
        """
        with open(path, 'r') as fh:
            lines = fh.readlines()
            return self.parse_lines(lines=lines)

    def _commit(self, ipver='v4'):
        """Internal function used by :py:meth:`.commit` to commit rule cache into output - see commit's PyDoc block."""
        log.debug('Committing IP%s cache to output', ipver)
        header = [f'*{self.table}']
        for cname, cdata in self.chains.items():
            header += [f':{cname} {cdata[0]} {cdata[1]}']
        merged = header + self.cache[ipver] + ['COMMIT', f'### End of table {self.table} ###']
        self.output[ipver] += merged
        self.cache[ipver] = []

    def commit(self, *args):
        """
        After an individual table has been parsed, :py:func:`.commit` is called, which:

         - Prepends the ``*table`` and chain definition headers and appends the ``COMMIT``` statement to the rules
         - Flushes the current IPv4 and IPv6 rules from :py:attr:`.cache` into :py:attr:`.output`
         - Sets :py:attr:`.chains` to match the known chains for the current table, in-case the table has changed.

        :param args:
        :return:
        """
        if len(self.cache.v4) > 0:
            self._commit('v4')

        if len(self.cache.v6) > 0:
            self._commit('v6')

        self.chains = self.DEFAULT_CHAINS.get(self.table, {})

    ###
    # Pyre Control Directive (e.g. ``@table``) handlers below.
    #
    # The below handling functions are designed to process the directive's arguments, and then take
    # the appropriate action required to fulfill the directive's purpose.
    ###

    def set_table(self, *args):
        """Handler for ``@table [table_name]`` directive in ``.pyre`` files."""
        table = args[0]
        if table.lower() == self.table.lower(): return
        log.debug('Setting table to "%s"', table)
        if not self.committed:
            self.commit()
        self.table = self.rp.table = table
        self.chains = self.rp.chains = dict(self.DEFAULT_CHAINS.get(self.table, {}))

    def set_chain(self, *args):
        """Handler for ``@chain [chain_name] (policy) (packets)`` directive in ``.pyre`` files."""
        if len(args) == 0:
            raise AttributeError('set_chain expects at least one argument')
        chain = args[0]
        policy = 'ACCEPT' if len(args) < 2 else args[1]
        packets = '[0:0]' if len(args) < 3 else args[2]
        log.debug('Setting chain %s to policy %s with packet counts "%s"', chain, policy, packets)
        self.chains[chain] = self.rp.chains[chain] = [policy, packets]

    def import_file(self, *args):
        """Handler for ``@import [file]`` directive in ``.pyre`` files."""
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
                if ftype == 'ip4': self.cache.v4 += [l.strip()]
                if ftype == 'ip6': self.cache.v6 += [l.strip()]
        log.info('Successfully imported "%s" ...', _path)

    control_handlers = {
        '@table': set_table,
        '@chain': set_chain,
        '@import': import_file,
    }
    """Maps each Pyre control directive such as ``@table`` to it's appropriate handling function"""
