import readline
import textwrap
import os
from typing import List

from privex.helpers import empty
from prompt_toolkit import PromptSession, print_formatted_text, ANSI
from prompt_toolkit.completion import Completer, WordCompleter
from prompt_toolkit.formatted_text import PygmentsTokens
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style, merge_styles, style_from_pygments_cls
from pygments.lexers.python import Python3Lexer
from privex.pyrewall import VERSION, PyreParser
import pygments.token
from colorama import Fore, Back
import logging

from privex.pyrewall.PyreLexer import PyreLexer
from pygments.styles.fruity import FruityStyle
from privex.pyrewall.core import columnize

log = logging.getLogger(__name__)

BLUE, GREEN, RED, YELLOW = Fore.BLUE, Fore.GREEN, Fore.RED, Fore.YELLOW
RESET = Fore.RESET

colorcodes = [getattr(Fore, c) for c in dir(Fore) if c[0] != '_']


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

    def emptyline(self):
        return

    def preloop(self):
        pass

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
            pyre_help_header = 'Pyre REPL Commands'
            self.print_topics(pyre_help_header, list(self.extra_cmds.keys()), 15, 80)

    def do_show(self, fmt=None, fmt2=None, *args):
        if fmt is not None:
            self.pyre = PyreParser()
            fmt_v4 = ['ipt', 'iptables', 'ip4', 'ipt4', 'iptables4']
            fmt_v6 = ['ipt6', 'ip6tables', 'ip6', 'iptables6']
            ip4, ip6 = self.pyre.parse_lines(self.buffer)
            if fmt in fmt_v4 or fmt2 in fmt_v4:
                msg('green', 'Current session parsed into IPv4 iptables rules:')
                msg('blue', '### Begin IPTables v4 Rules ###')
                for l in ip4:
                    print(l)
                msg('blue', '### End IPTables v4 Rules ###')

            if fmt in fmt_v6 or fmt2 in fmt_v6:
                msg('green', 'Current session parsed into IPv6 iptables rules:')
                msg('blue', '### Begin IPTables v6 Rules ###')
                for l in ip6:
                    print(l)
                msg('blue', '### End IPTables v6 Rules ###')
            return

        msg('green', 'Current PyreWall rules executed during this session:')
        msg('### Begin Pyre Rules ###')
        tokens = list()
        for l in self.buffer:
            if empty(l.strip()): continue
            tokens += list(pygments.lex(l.strip(), lexer=PyreLexer()))
        print_formatted_text(PygmentsTokens(tokens), style=self.style, end='')
        # print(l.strip())
        msg('### End Pyre Rules ###')

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


    def default(self, line):
        return self.parse_lines(*line.split('\n'))
        # line = str(line).strip()
        # if '\n' in line:
        #     lines = line.split('\n')
        #
        #
        # l = line.split()
        # if len(l) == 0: return
        # cmdname, args = l[0].strip(), l[1:]
        #
        # cmds = [d for d in dir(self.__class__) if d[0:3] == 'do_']
        # if 'do_' + cmdname in cmds:
        #     log.info('Calling %s', 'do_' + cmdname)
        #     return getattr(self, 'do_' + cmdname)(*args)
        # if cmdname in self.extra_cmds:
        #     log.info('Calling extra cmd %s', cmdname)
        #     return self.extra_cmds[cmdname](self, *args)
        #
        # try:
        #     # noinspection PyProtectedMember
        #     v4r, v6r = self.pyre._parse(line=line)
        #     if v4r is None and v6r is None:
        #         msg('yellow', "Warning: The line entered does not appear to be a valid command, nor valid Pyre.")
        #         return
        #     self.buffer.append(line)
        #     if len(v4r) > 0:
        #         msg('blue', '### IPv4 Rules ###')
        #         for r in v4r:
        #             print(r)
        #         msg('blue', '### End IPv4 Rules ###\n')
        #     if len(v6r) > 0:
        #         msg('blue', '### IPv6 Rules ###')
        #         for r in v6r:
        #             print(r)
        #         msg('blue', '### End IPv6 Rules ###\n')
        #
        # except (BaseException, Exception) as e:
        #     msg('red', 'Got exception while parsing Pyre line!')
        #     msg('red', 'Exception:', type(e), str(e))
        #     return

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
    if len(args) == 0: return print_formatted_text()
    if args[0].lower() in ['red', 'blue', 'green', 'yellow']:
        return print_formatted_text(ANSI(_msg(*args)))
    print_formatted_text()


pyre_repl = PyreRepl()


def repl_main(*args, **kwargs):
    print(header)
    # screen = get_screen()

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
