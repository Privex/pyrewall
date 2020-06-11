import subprocess
import sys
from collections import namedtuple
from os.path import join, expanduser
from typing import List, Union
from privex.helpers import run_sync, byteify, empty, stringify
from privex.pyrewall.exceptions import InvalidPort, IPTablesError, ReturnCodeError
from privex.pyrewall import conf
from subprocess import PIPE, STDOUT
import logging
import os.path

log = logging.getLogger(__name__)


def find_file(filename: str, paths: List[str] = None, extensions=None) -> str:
    """
    Attempt to find a file in a given list of paths

    Usage:

        >>> find_file('test')
        /etc/pyrewall/test.pyre
        >>> find_file('example.v4', paths=['/etc', '/etc/test'], extensions=[''])
        /etc/example.v4


    :param str filename: A filename, relative path, or absolute file path
    :param List[str] paths: A list of paths to search for ``filename`` within
    :param List[str] extensions: A list of filename extensions to try suffixing if the exact name can't be found

    :raises FileNotFoundError: When the ``filename`` could not be found in any of the given paths or with extensions.

    :return str path: If the file was found, returns an absolute path to the matched file
    """

    extensions = conf.SEARCH_EXTENSIONS if not extensions else extensions
    paths = conf.SEARCH_DIRS if not paths else paths

    if '' not in extensions:
        extensions += ['']

    if os.path.isabs(filename):
        with open(filename, 'r'):
            return filename

    for ext in extensions:
        _fn = [f'{filename}{ext}']
        if '/' in filename:
            _fn = list(filename.split('/'))
            _fn[-1] = f'{_fn[-1]}{ext}'

        for p in paths:
            fpath = join(expanduser(p), *_fn)
            try:
                with open(fpath, 'r'):
                    return fpath
            except FileNotFoundError:
                continue

    raise FileNotFoundError(f'File "{filename}" could not be found in any of the given paths.')


def search_files(*filenames, paths: List[str] = None, extensions=None) -> str:
    orig_filenames = list(filenames)
    filenames = list(filenames)
    while len(filenames) > 0:
        f = filenames.pop(0)
        try:
            fpath = find_file(filename=f, paths=paths, extensions=extensions)
            return fpath
        except FileNotFoundError:
            continue
    
    raise FileNotFoundError(f'The filenames "{orig_filenames}" could not be found in any of the given paths.')


def valid_port(port: Union[str, int]) -> int:
    """Returns the integer port if it's valid. Otherwise raises :class:`.InvalidPort` """
    try:
        port = int(port)
        if port > 65535 or port < 1:
            raise InvalidPort
        return port
    except Exception:
        raise InvalidPort(f'Port number "{port}" is not a valid port number')


def columnize(items, displaywidth=80):
    """Display a items of strings as a compact set of columns.

    Each column is only as wide as necessary.
    Columns are separated by two spaces (one was not legible enough).
    """
    if not items:
        print("<empty>\n")
        return

    nonstrings = [i for i in range(len(items))
                  if not isinstance(items[i], str)]
    if nonstrings:
        raise TypeError("items[i] not a string for i in %s" % ", ".join(map(str, nonstrings)))
    size = len(items)
    if size == 1:
        print('%s\n' % str(items[0]))
        return
    # Try every row count from 1 upwards
    for nrows in range(1, len(items)):
        ncols = (size + nrows - 1) // nrows
        colwidths = []
        totwidth = -2
        for col in range(ncols):
            colwidth = 0
            for row in range(nrows):
                i = row + nrows * col
                if i >= size:
                    break
                x = items[i]
                colwidth = max(colwidth, len(x))
            colwidths.append(colwidth)
            totwidth += colwidth + 2
            if totwidth > displaywidth:
                break
        if totwidth <= displaywidth:
            break
    else:
        nrows = len(items)
        ncols = 1
        colwidths = [0]
    for row in range(nrows):
        texts = []
        for col in range(ncols):
            i = row + nrows * col
            if i >= size:
                x = ""
            else:
                x = items[i]
            texts.append(x)
        while texts and not texts[-1]:
            del texts[-1]
        for col in range(len(texts)):
            texts[col] = texts[col].ljust(colwidths[col])
        print("%s\n" % str("  ".join(texts)))


def is_root() -> bool:
    uid = os.geteuid()
    if uid != 0:
        log.debug("Current UID '%s' is not 0 (root).", uid)
        return False
    return True


ProcResult = namedtuple('ProcResult', 'stdout stderr code', defaults=[0])


def run_prog(prog: str, *args, write=None, **kwargs):
    stdout, stderr, stdin = kwargs.pop('stdout', PIPE), kwargs.pop('stderr', STDOUT), kwargs.pop('stdin', PIPE)
    args = [prog] + list(args)
    handle = subprocess.Popen(args, stdout=stdout, stderr=stderr, stdin=stdin, **kwargs)
    stdout, stderr = handle.communicate(input=byteify(write)) if write is not None else handle.communicate()
    
    return ProcResult(stdout=stdout, stderr=stderr, code=int(handle.returncode))


def run_prog_ex(prog: str, *args, write=None, **kwargs):
    cmd = [prog] + list(args)
    res = run_prog(prog, *args, write=write, **kwargs)
    
    if res.code != 0:
        log.error(f"ERROR! Non-zero return code ({res.code}) from command: {cmd}")
        log.error("Command stdout: %s", res.stdout)
        log.error("Command stderr: %s", res.stderr)
        raise ReturnCodeError(f"Non-zero return code ({res.code}) from command: {cmd}")
    
    log.info(f"Got successful (zero) exit code from command: {cmd}")
    log.info("Command stdout: %s", res.stdout)
    log.info("Command stderr: %s", res.stderr)
    return res


def save_rules(ipver='v4') -> List[str]:
    cmd = [] if is_root() else ['sudo', '-n']
    cmd += ['iptables-save'] if ipver in ['v4', '4', 'ipv4', 4] else ['ip6tables-save']
    
    res = run_prog(*cmd)
    
    if res.code != 0:
        log.error(f"ERROR! Non-zero return code ({res.code}) from command: {cmd}")
        log.error("Command stdout: %s", res.stdout)
        log.error("Command stderr: %s", res.stderr)
        raise IPTablesError(f"Non-zero return code ({res.code}) from command: {cmd}")
    
    return stringify(res.stdout).split("\n")


def load_rules(rules: Union[str, list], ipver='v4'):
    cmd = [] if is_root() else ['sudo', '-n']
    cmd += ['iptables-restore'] if ipver in ['v4', '4', 'ipv4', 4] else ['ip6tables-restore']
    
    if isinstance(rules, str):
        cmd += [rules]
        log.info("Restoring IPTables file %s using command %s", rules, cmd)
        res = run_prog(*cmd)
        
        # print(f"Rules file {rules} appeared to restore successfully :)\n", file=sys.stderr)
    else:
        rule_list = list(rules)
        rule_list = [r.strip("\n").strip() for r in rule_list if not empty(r.strip("\n").strip())]
        l_rules = "\n".join(rule_list)
        res = run_prog(*cmd, write=l_rules)

    if res.code != 0:
        log.error(f"ERROR! Non-zero return code ({res.code}) from command: {cmd}")
        log.error("Command stdout: %s", res.stdout)
        log.error("Command stderr: %s", res.stderr)
        raise IPTablesError(f"Non-zero return code ({res.code}) from command: {cmd}")
    
    log.debug(f"Got successful (zero) exit code from command: {cmd}")
    log.debug("Command stdout: %s", res.stdout)
    log.debug("Command stderr: %s", res.stderr)
    
    return res

    
    
    
    
    

