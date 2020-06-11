"""
+===================================================+
|                 © 2019 Privex Inc.                |
|               https://www.privex.io               |
+===================================================+
|                                                   |
|        PyreWall - Python iptables firewall tool   |
|        License: X11/MIT                           |
|                                                   |
|        Core Developer(s):                         |
|                                                   |
|          (+)  Chris (@someguy123) [Privex]        |
|                                                   |
+===================================================+

PyreWall - A Python tool / service for managing iptables firewalls with ease
Copyright (c) 2019    Privex Inc. ( https://www.privex.io )

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, 
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS 
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name(s) of the above copyright holders shall not be used in advertising or 
otherwise to promote the sale, use or other dealings in this Software without prior written authorization.
"""
import sys

from privex.pyrewall.conf import LOG_LEVEL
from privex.pyrewall.core import find_file, valid_port
from privex.pyrewall.RuleParser import RuleParser
from privex.pyrewall.RuleBuilder import RuleBuilder
from privex.pyrewall.PyreParser import PyreParser
from privex.pyrewall.types import IPT_ACTION, IPT_TYPE
from privex.pyrewall.exceptions import RuleSyntaxError, InvalidPort
from privex.loghelper import LogHelper

name = 'pyrewall'
VERSION = '0.10.0'

_lh = LogHelper(__name__, handler_level=LOG_LEVEL)

_lh.add_console_handler(stream=sys.stderr)
