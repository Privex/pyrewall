import logging
from os.path import join, dirname, abspath
from os import getenv as env, getcwd
from privex.helpers import env_csv, env_bool
import dotenv


PKG_DIR = dirname(abspath(__file__))
"""Package installation folder (e.g. site-packages/privex/pyrewall) containing this file"""

BASE_DIR = dirname(dirname(dirname(abspath(__file__))))
"""Base folder of the project, i.e. where setup.py and LICENSE are located"""

SERVICE_FILE = join(PKG_DIR, 'files', 'pyrewall.service')
SERVICE_FILE_DEST = '/etc/systemd/system/pyrewall.service'

CONF_DIRS = [
    '/etc/pyrewall',
    '/usr/local/etc/pyrewall',
    '~/.pyrewall',
    join(BASE_DIR, 'configs'),
    join(PKG_DIR, 'configs'),
]
"""
CONF_DIRS is used when searching for config files to load during either:

 - Reloading Pyrewall (search those folders for files ending in our suffixes)
 - Importing config files without an absolute path from within Pyrewall configs

"""

SEARCH_DIRS = [
    getcwd()
] + CONF_DIRS
"""
SEARCH_DIRS controls the order of paths to scan when loading an individual .pyre
file from the CLI

For convenience, the current working directory takes priority for SEARCH_DIRS
"""

# Load .env file (search through SEARCH_DIRS, BASE_DIR, as well as dotenv's auto finding)
for d in SEARCH_DIRS:
    dotenv.load_dotenv(join(d, '.env'))

dotenv.load_dotenv(join(BASE_DIR, '.env'))
dotenv.load_dotenv()

DEBUG = env_bool('DEBUG', False)

CONF_DIRS = env_csv('CONF_DIRS', CONF_DIRS)
SEARCH_DIRS = env_csv('SEARCH_DIRS', SEARCH_DIRS)

FILE_SUFFIX = env('FILE_SUFFIX', '.pyre')
IPT4_SUFFIX = env('IPT4_SUFFIX', '.v4')
IPT6_SUFFIX = env('IPT6_SUFFIX', '.v6')


SEARCH_EXTENSIONS = env_csv('SEARCH_EXTENSIONS', ['', FILE_SUFFIX, IPT4_SUFFIX, IPT6_SUFFIX])

MAIN_PYRE = [
    f'rules{FILE_SUFFIX}', f'main{FILE_SUFFIX}', f'master{FILE_SUFFIX}', f'base{FILE_SUFFIX}',
    f'firewall{FILE_SUFFIX}'
]
"""
A list of default 'master' Pyrewall rule files to try and locate and use, if one isn't specified on the command line.

These will be searched for in order, within each :attr:`.SEARCH_DIRS`, until a matching file is found.
"""

MAIN_PYRE = env_csv('MAIN_PYRE', MAIN_PYRE)

# Valid environment log levels (from least to most severe) are:
# DEBUG, INFO, WARNING, ERROR, FATAL, CRITICAL
LOG_LEVEL = env('LOG_LEVEL', None)
LOG_LEVEL = logging.getLevelName(str(LOG_LEVEL).upper()) if LOG_LEVEL is not None else None

if LOG_LEVEL is None:
    LOG_LEVEL = logging.DEBUG if DEBUG else logging.INFO

EXTENSION_TYPES = {
    FILE_SUFFIX: 'pyre',
    IPT4_SUFFIX: 'ip4',
    IPT6_SUFFIX: 'ip6',
}

DEFAULT_CHAINS = {
    'filter': {
        'INPUT': ['ACCEPT', '[0:0]'],
        'FORWARD': ['ACCEPT', '[0:0]'],
        'OUTPUT': ['ACCEPT', '[0:0]'],
    },
    'nat': {
        'PREROUTING': ['ACCEPT', '[0:0]'],
        'INPUT': ['ACCEPT', '[0:0]'],
        'OUTPUT': ['ACCEPT', '[0:0]'],
        'POSTROUTING': ['ACCEPT', '[0:0]'],
    }
}

