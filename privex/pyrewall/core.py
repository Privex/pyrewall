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

