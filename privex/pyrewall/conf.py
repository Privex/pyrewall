from os.path import join, dirname, abspath
from os import getenv as env, getcwd
from privex.helpers import env_csv

BASE_DIR = dirname(dirname(dirname(abspath(__file__))))
"""Base folder of the project, i.e. where setup.py and LICENSE are located"""

CONF_DIRS = [
    '/etc/pyrewall',
    '/usr/local/etc/pyrewall',
    join(BASE_DIR, 'configs')
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

CONF_DIRS = env_csv('CONF_DIRS', CONF_DIRS)
SEARCH_DIRS = env_csv('SEARCH_DIRS', SEARCH_DIRS)

FILE_SUFFIX = env('FILE_SUFFIX', '.pyre')
IPT4_SUFFIX = env('IPT4_SUFFIX', '.v4')
IPT6_SUFFIX = env('IPT6_SUFFIX', '.v6')
