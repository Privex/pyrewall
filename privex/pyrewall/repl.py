import readline
import textwrap
import os
import pygments.token
import logging
from colorama import Fore, Back
from typing import List, Iterable
from privex.helpers import empty, DictObject
from prompt_toolkit import PromptSession, print_formatted_text, ANSI
from prompt_toolkit.completion import Completer, WordCompleter
from prompt_toolkit.formatted_text import PygmentsTokens
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style, merge_styles, style_from_pygments_cls
from pygments.lexers.python import Python3Lexer
from pygments.styles.fruity import FruityStyle

from privex.pyrewall import VERSION, PyreParser
from privex.pyrewall.core import columnize, find_file
from privex.pyrewall.PyreLexer import PyreLexer

log = logging.getLogger(__name__)

BLUE, GREEN, RED, YELLOW = Fore.BLUE, Fore.GREEN, Fore.RED, Fore.YELLOW
RESET = Fore.RESET

colorcodes = [getattr(Fore, c) for c in dir(Fore) if c[0] != '_']

fmt_v4 = ['ipt', 'iptables', 'ip4', 'ipt4', 'iptables4', 'v4']
fmt_v6 = ['ipt6', 'ip6tables', 'ip6', 'iptables6', 'v6']


class PyreRepl:
    file = None

    buffer: List[str]
    pyre = PyreParser()
    hist_file_name = '.pyre_repl_history'

    style = merge_styles([
        style_from_pygments_cls(FruityStyle),
        Style.from_dict({
            '': '#0a0eff',
            'pygments.text': '#0a0eff',
            'prompt': '#00ff00 bold',
            'pygments.number': '#7ec0ee'
        })
    ])
    prompt = [('class:prompt', ' Pyre >> ')]

    ruler = '='

    def __init__(self, *args, **kwargs):
        self.buffer = []
        self.hist_file = os.path.expanduser(f'~/{self.hist_file_name}')
        self.should_exit = False
        self.keywords = list(self.pyre.control_handlers.keys()) + list(self.pyre.rp.rule_handlers.keys())
        self.completer = WordCompleter(self.keywords)
        open(self.hist_file, 'a').close()
        self.session = PromptSession(history=FileHistory(self.hist_file))
        self._rendered_rules = DictObject(v4=[], v6=[], pyre=[])
        self.rendered_at = len(self.buffer)
    
    def emptyline(self):
        return

    def preloop(self):
        pass


    def print_header(self, header, color=None):
        color = 'NO_COLOR' if color is None else color
        msg(color, header)
        msg(f"{self.ruler * len(header)}\n")

    def print_topics(self, header, cmds, cmdlen, maxcol):
        if cmds:
            msg('blue', str(header))
            if self.ruler:
                print("%s" % str(self.ruler * len(header)))
            print(GREEN)
            columnize(cmds, maxcol - 1)
            print(RESET)

    def do_exit(self, *args):
        self.should_exit = True

    def do_help(self, *args):
        """List available commands with "help" or detailed help with "help cmd"."""
        if len(args) == 0:
            self.print_header("Privex Pyrewall REPL - Help", 'yellow')
            msg("Using this REPL, you can experiment with the Privex Pyre fireall configuration language.")
            msg("Just start typing a Pyre rule, and the REPL will assist you, with drop-down suggestions and tab completion.\n")
            msg("Some examples to try:\n")
            msg('green', "\t @chain INPUT DROP\n\t @chain FORWARD DROP\n")
            msg('green', "\t allow port 21 from 2a07:e01::1,192.168.8.1")
            msg('green', "\t allow all from 2a07:e00::/32")
            msg('green', "\t allow chain input,forward state related,established")
            msg('green', "\t allow port 6000-7000 udp")
            msg('green', "\t allow port 9090,1010 both from 10.0.0.1,2a07:e01::/32")
            msg('\n')
            msg("You can print the current REPL session as Pyre, IPTables v4, or IPTables v6:\n")
            msg('yellow', "\t # Print the current session as syntax highlighted Pyre")
            msg('green', "\t \\print")
            msg('yellow', "\t # Print the current session as IPv4 IPTables persistent format")
            msg('green', "\t \\print ip4")
            msg()
            msg("Type '\\? [command]' e.g. '\\? output' to show full help for a REPL command.\n")
            # msg("%s" % str(self.ruler * len(header)))
            pyre_help_header = 'Pyre REPL Commands'
            self.print_topics(pyre_help_header, list(self.extra_cmds.keys()), 15, 80)
            return
        
        if args[0] in ['print', 'show', '\\print', '\\show']:
            return self._help_show()
        
        if args[0] in ['out', 'output', '\\out', '\\output']:
            return self._help_output()
        
        msg('red', f"Invalid help topic '{args[0]}'... Type '\\?' or 'help' for general help.\n")

    @property
    def rendered_rules(self) -> DictObject:
        if self.rendered_at != len(self.buffer) or self.pyre is None:
            self.pyre = PyreParser()
            ip4, ip6 = self.pyre.parse_lines(self.buffer)
            self._rendered_rules['v4'], self._rendered_rules['v6'] = ip4, ip6
            self._rendered_rules['pyre'] = list(self.buffer)
            self.rendered_at = len(self.buffer)
        return self._rendered_rules
    
    def _show_ip_rules(self, ipver='v4'):
        msg('green', f'Current session parsed into IP{ipver} iptables rules:')
        msg('blue', f'### Begin IPTables {ipver} Rules ###')
        for l in self.rendered_rules[ipver]:
            print(l)
        msg('blue', f'### End IPTables {ipver} Rules ###')

    def _show_pyre_rules(self):
        msg('green', 'Current PyreWall rules executed during this session:')
        msg('### Begin Pyre Rules ###')
        tokens = list()
        for l in self.buffer:
            if empty(l.strip()): continue
            tokens += list(pygments.lex(l.strip(), lexer=PyreLexer()))
        print_formatted_text(PygmentsTokens(tokens), style=self.style, end='')
        msg('### End Pyre Rules ###')

    def _help_output(self):
        msg('green', 'Usage: \\output [format=ip4|ip6|pyre] [file]')
        msg('Examples:\n')
        msg('yellow', "\t # Output the current session in Pyre format to hello.pyre in the current folder")
        msg('green', "\t \\output pyre hello.pyre")
        msg('yellow', "\t # Output as IPv4 IPTables persistent format into rules.v4 in the current folder")
        msg('green', "\t \\output ip4 rules.v4")
        msg('yellow', "\t # Output as IPv6 IPTables persistent format into rules.v6 in the current folder")
        msg('green', "\t \\output ip6 rules.v6")
        msg()
    
    def _help_show(self):
        msg('green', 'Usage: \\show format [format2] [format3..] (formats: ip4|ip6|pyre)')
        msg('green', 'Usage: \\print format [format2] [format3..] (formats: ip4|ip6|pyre)')
        msg("You can print the current REPL session as Pyre, IPTables v4, or IPTables v6\n")
        msg('Examples:\n')
        msg('yellow', "\t # Print the current session as syntax highlighted Pyre")
        msg('green', "\t \\show")
        msg('yellow', "\t # Print the current session as IPv4 IPTables persistent format")
        msg('green', "\t \\show ip4")
        msg('yellow', "\t # Print the current session as IPv6 IPTables persistent format")
        msg('green', "\t \\show ip6")
        msg('yellow', "\t # Print the current session in both IPv4 + IPv6 IPTables persistent formats")
        msg('green', "\t \\show both")
        msg('green', "\t \\show ip4 ip6")
        msg('yellow', "\t # Print the current session in Pyre, and IPv4 + IPv6 IPTables persistent formats")
        msg('green', "\t \\show all")
        msg('green', "\t \\show ip4 ip6 pyre")
        msg()

    def _output_lines(self, out_file: str, lines: Iterable):
        i = 0
        with open(out_file, 'w') as fh:
            for l in lines:
                l = l.strip('\n').strip()
                fh.write(f"{l}\n")
                i += 1
        return i
        
    def do_output(self, out_format=None, out_file=None, *args):
        if empty(out_format) or empty(out_file):
            msg('yellow', 'Invalid command usage for \\output.')
            return self._help_output()
        fmt_pyre = ['pyre', '.pyre', 'pyrewall']
        
        if out_format in fmt_v4:
            msg('green', f"Outputting session as IPv4 IPTables format to file {out_file}")
            count = self._output_lines(out_file=out_file, lines=self.rendered_rules.v4)
        elif out_format in fmt_v6:
            msg('green', f"Outputting session as IPv6 IPTables format to file {out_file}")
            count = self._output_lines(out_file=out_file, lines=self.rendered_rules.v6)
        elif out_format in fmt_pyre:
            msg('green', f"Outputting session as native Pyrewall 'pyre' format to file {out_file}")
            count = self._output_lines(out_file=out_file, lines=self.rendered_rules.pyre)
        else:
            msg('yellow', f"Invalid output format '{out_format}' for \\output.")
            return self._help_output()
        msg('green', f"Sucessfully wrote {count} lines to file {out_file}")
    
    def do_show(self, *args):
        # fmt_v4 = ['ipt', 'iptables', 'ip4', 'ipt4', 'iptables4', 'v4', 'both', 'all']
        # fmt_v6 = ['ipt6', 'ip6tables', 'ip6', 'iptables6', 'v6', 'both', 'all']

        for a in args:
            if a in list(fmt_v4) + ['both', 'all']:
                self._show_ip_rules('v4')
            if a in list(fmt_v6) + ['both', 'all']:
                self._show_ip_rules('v6')
            if a in ['pyre', '.pyre', 'rules', 'pyrewall', 'all']:
                self._show_pyre_rules()
        
        if len(args) == 0:
            self._show_pyre_rules()

        # if fmt is not None:
        #     self.pyre = PyreParser()
        #     fmt_v4 = ['ipt', 'iptables', 'ip4', 'ipt4', 'iptables4']
        #     fmt_v6 = ['ipt6', 'ip6tables', 'ip6', 'iptables6']
        #     ip4, ip6 = self.pyre.parse_lines(self.buffer)
        #     if fmt in fmt_v4 or fmt2 in fmt_v4:
        #         msg('green', 'Current session parsed into IPv4 iptables rules:')
        #         msg('blue', '### Begin IPTables v4 Rules ###')
        #         for l in ip4:
        #             print(l)
        #         msg('blue', '### End IPTables v4 Rules ###')

        #     if fmt in fmt_v6 or fmt2 in fmt_v6:
        #         msg('green', 'Current session parsed into IPv6 iptables rules:')
        #         msg('blue', '### Begin IPTables v6 Rules ###')
        #         for l in ip6:
        #             print(l)
        #         msg('blue', '### End IPTables v6 Rules ###')
        #     return

        # msg('green', 'Current PyreWall rules executed during this session:')
        # msg('### Begin Pyre Rules ###')
        # tokens = list()
        # for l in self.buffer:
        #     if empty(l.strip()): continue
        #     tokens += list(pygments.lex(l.strip(), lexer=PyreLexer()))
        # print_formatted_text(PygmentsTokens(tokens), style=self.style, end='')
        # # print(l.strip())
        # msg('### End Pyre Rules ###')

    def parse_lines(self, *lines):
        v4r, v6r = [], []
        msg()
        for ln in lines:
            l = ln.split()
            if len(l) == 0: continue
            cmdname, args = l[0].strip(), l[1:]

            cmds = [d for d in dir(self.__class__) if d[0:3] == 'do_']
            if 'do_' + cmdname in cmds:
                getattr(self, 'do_' + cmdname)(*args)
                continue

            if cmdname in self.extra_cmds:
                self.extra_cmds[cmdname](self, *args)
                continue

            try:
                _v4r, _v6r = self.pyre._parse(line=ln)
                if _v4r is None and _v6r is None:
                    msg('yellow', "# Warning: The line entered does not appear to be a valid command, nor valid Pyre.")
                    continue
                self.buffer.append(ln)
                v4r += _v4r
                v6r += _v6r
            except (BaseException, Exception) as e:
                msg('red', 'Got exception while parsing Pyre line!')
                msg('red', 'Exception:', type(e), str(e))
                return
        if len(v4r) > 0:
            msg('blue', '### IPv4 Rules ###')
            for r in v4r:
                print(r)
            msg('blue', '### End IPv4 Rules ###\n')
        if len(v6r) > 0:
            msg('blue', '### IPv6 Rules ###')
            for r in v6r:
                print(r)
            msg('blue', '### End IPv6 Rules ###\n')
        msg()

    def parse_file(self, filename: str, **kwargs):
        fl = find_file(filename, **kwargs)
        msg('yellow', f"Parsing file: {fl}")
        with open(fl, 'r') as fh:
            self.parse_lines(*fh.readlines())

    def default(self, line):
        return self.parse_lines(*line.split('\n'))

    def do_py(self, *args):
        """Execute raw python code for debugging purposes"""
        print(eval(' '.join(args)))

    def precmd(self, line):
        return

    def postcmd(self, line):
        readline.set_auto_history(False)
        return self.should_exit

    def cmdloop(self):
        while not self.should_exit:
            data = self.session.prompt(
                self.prompt, lexer=PygmentsLexer(PyreLexer), style=self.style, completer=self.completer
            )
            self.precmd(data)
            self.default(data)
            self.postcmd(data)

    extra_cmds = {
        '\\?': do_help,
        '\\print': do_show,
        '\\output': do_output,
        '\\show': do_show,
    }


def get_color(name): return getattr(Fore, name.upper(), None)


header = textwrap.dedent(f'''
{YELLOW}PyreWall Version v{VERSION}
(C) 2019 Privex Inc. ( https://wwww.privex.io )
Official Repo: https://github.com/Privex/pyrewall{RESET}
''')


def _msg(*args):
    args = [str(a) for a in args]
    if len(args) == 0:
        return ''

    out = ' '.join(args)
    if args[0] in colorcodes:
        out = args.pop(0) + ' '.join(args) + str(RESET)
    elif get_color(args[0]) is not None:
        out = get_color(args.pop(0)) + ' '.join(args) + str(RESET)

    return out


def msg(*args, eol="\n", **kwargs):
    # print(_msg(*args), end=eol)
    args = list(args)
    if len(args) == 0: return print_formatted_text()
    if args[0].lower() in ['red', 'blue', 'green', 'yellow']:
        return print_formatted_text(ANSI(_msg(*args)))
    if args[0].lower() == 'NO_COLOR':
        args.pop(0)
        return print_formatted_text(*args)
    
    print_formatted_text(*args)


pyre_repl = PyreRepl()


def repl_main(*args, files=None, **kwargs):
    print(header)
    # screen = get_screen()
    if not empty(files, itr=True):
        if isinstance(files, str):
            pyre_repl.parse_file(files)
        elif isinstance(files, (list, tuple, set)):
            for f in files:
                pyre_repl.parse_file(f)
        else:
            msg('red', f"ERROR: Unknown object type for 'files': {type(files)} - files contents: {files}")
    
    msg(
        'green',
        'Welcome to the PyreWall REPL - a playground for Pyre syntax. Simply type Pyre language lines such',
        'as "allow port 80,443 from 1.2.3.4", and the resulting IPTables rules will be outputted.'
    )
    msg('yellow', 'For help, type \\? or "help"\n')

    try:
        pyre_repl.cmdloop()
    except EOFError:
        return
    except (BaseException, Exception, AttributeError):
        log.exception('Exception from cmdloop')
