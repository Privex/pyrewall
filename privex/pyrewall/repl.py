import atexit
import readline
import sys
import textwrap
import curses
import os
from cmd import Cmd
from os.path import join
from typing import List
from os import getenv as env
from privex.helpers import empty

from privex.pyrewall import VERSION, PyreParser
from colorama import Fore, Back
import logging

log = logging.getLogger(__name__)

BLUE, GREEN, RED, YELLOW = Fore.BLUE, Fore.GREEN, Fore.RED, Fore.YELLOW
RESET = Fore.RESET

colorcodes = [getattr(Fore, c) for c in dir(Fore) if c[0] != '_']


#hist_file =

class PyreRepl(Cmd):
    file = None
    prompt = " Pyre >> "
    extra_cmds = {
        '\\?': Cmd.do_help
    }
    buffer: List[str]
    pyre = PyreParser()
    hist_file_name = '.pyre_repl_history'

    def __init__(self, *args, **kwargs):
        self.buffer = []
        self.hist_len = 0
        self.hist_file = None
        self.history = []
        self.should_exit = False
        readline.set_auto_history(False)
        super().__init__(*args, **kwargs)

    def emptyline(self):
        return

    def preloop(self):
        # if empty(env('HOME')):
        #     self.hist_file = None
        #     return msg('red', 'WARNING: $HOME is undefined. Not saving REPL history...')
        self.hist_file = os.path.join(os.path.expanduser("~"), self.hist_file_name)
        readline.set_auto_history(False)
        readline.set_history_length(1000)
        try:
            # with open(self.hist_file, 'r'):
            #     log.debug('Successfully opened history file')
            readline.read_history_file(self.hist_file_name)
        except FileNotFoundError:
            log.info("No history file at '%s' ", self.hist_file_name)
            # open(self.hist_file, 'a').close()
            pass
        atexit.register(self.save_history)
        msg('green', f'Saving REPL history to {self.hist_file}')

    def print_topics(self, header, cmds, cmdlen, maxcol):
        if cmds:
            msg('blue', str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            self.stdout.write(GREEN)
            self.columnize(cmds, maxcol - 1)
            self.stdout.write(RESET + "\n")

    def do_exit(self, arg=None):
        self.should_exit = True
        return ''

    def do_help(self, arg):
        """List available commands with "help" or detailed help with "help cmd"."""
        super().do_help(arg=arg)
        if not arg:
            pyre_help_header = 'Pyre REPL Commands'
            self.print_topics(pyre_help_header, list(self.extra_cmds.keys()), 15, 80)

    def do_show(self, arg):
        arg = arg.split()
        msg('green', 'Current PyreWall rules executed during this session:')
        msg('### Begin Pyre Rules ###')
        for l in self.buffer:
            print(l.strip())
        msg('### End Pyre Rules ###')

    def default(self, line):
        line = str(line).strip()
        l = line.split()
        cmdname = l[0].strip()
        arg = ' '.join(l[1:])
        if cmdname in self.extra_cmds:
            return self.extra_cmds[cmdname](self, arg)

        try:
            # noinspection PyProtectedMember
            v4r, v6r = self.pyre._parse(line=line)
            self.buffer.append(line)
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

        except (BaseException, Exception) as e:
            msg('red', 'Got exception while parsing Pyre line!')
            msg('red', 'Exception:', type(e), str(e))
            return

    def do_py(self, arg=''):
        """Execute raw python code for debugging purposes"""
        print(eval(arg))

    def precmd(self, line):
        readline.set_auto_history(False)
        if line == 'EOF':
            self.should_exit = True
            return ''
        if not empty(line):
            # self.history += [line]
            self.hist_len += 1
            readline.add_history(line.strip())
            print('Current history len:', readline.get_current_history_length())
        return super().precmd(line)

    def postcmd(self, stop, line):
        readline.set_auto_history(False)
        return stop or self.should_exit

    def save_history(self):
        readline.set_history_length(1000)
        # readline.write_history_file(self.hist_file)
        readline.append_history_file(self.hist_len, self.hist_file_name)
        msg('green', f'Saved REPL history to {self.hist_file}')


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


def msg(*args, eol="\n"):
    print(_msg(*args), end=eol)


readline.set_auto_history(False)
pyre_repl = PyreRepl()
pyre_repl.prompt = " Pyre >> "


def repl_main(*args, **kwargs):
    print(header)
    # screen = get_screen()

    msg(
        'green',
        'Welcome to the PyreWall REPL - a playground for Pyre syntax. Simply type Pyre language lines such',
        'as "allow port 80,443 from 1.2.3.4", and the resulting IPTables rules will be outputted.'
    )

    try:
        pyre_repl.cmdloop(intro='For help, type \\? or "help"\n')
    except (BaseException, Exception, AttributeError):
        log.exception('Exception from cmdloop')
