from os.path import join
from typing import List, Union
from privex.pyrewall.exceptions import InvalidPort
from privex.pyrewall import conf
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
            fpath = join(p, *_fn)
            try:
                with open(fpath, 'r'):
                    return fpath
            except FileNotFoundError:
                continue

    raise FileNotFoundError(f'File "{filename}" could not be found in any of the given paths.')


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

