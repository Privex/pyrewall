import re
from pygments.lexer import *
from pygments.lexers.python import *
from pygments.token import *
from pygments import unistring as uni
from pygments.util import shebang_matches
from privex.pyrewall.PyreParser import PyreParser
from privex.pyrewall.RuleParser import RuleParser


class PyreLexer(RegexLexer):
    """
    Lexer for syntax highlighting PyreWall files
    """

    name = 'PyreWall'
    aliases = ['pyrewall', 'pyre']
    filenames = []  # Nothing until Python 3 gets widespread
    mimetypes = ['text/x-pyrewall', 'application/x-pyrewall']

    ipv6_address = r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{' \
                   r'2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[' \
                   r'0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[' \
                   r'0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,' \
                   r'4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[' \
                   r'0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[' \
                   r'0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,' \
                   r'4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[' \
                   r'0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[' \
                   r'0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(' \
                   r'?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,' \
                   r'4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[' \
                   r'0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{' \
                   r'1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[' \
                   r'0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[' \
                   r'0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,' \
                   r'6}[0-9A-Fa-f]{1,4})?::)(/?([0-9]+)?)?'

    ipv4_address = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    flags = re.MULTILINE | re.UNICODE

    uni_name = "[%s][%s]*" % (uni.xid_start, uni.xid_continue)

    def innerstring_rules(ttype):
        return [
            # the old style '%s' % (...) string formatting (still valid in Py3)
            (r'%(\(\w+\))?[-#0 +]*([0-9]+|[*])?(\.([0-9]+|[*]))?'
             '[hlL]?[E-GXc-giorsaux%]', String.Interpol),
            # the new style '{}'.format(...) string formatting
            (r'\{'
             r'((\w+)((\.\w+)|(\[[^\]]+\]))*)?'  # field name
             r'(\![sra])?'                       # conversion
             r'(\:(.?[<>=\^])?[-+ ]?#?0?(\d+)?,?(\.\d+)?[E-GXb-gnosx%]?)?'
             r'\}', String.Interpol),

            # backslashes, quotes and formatting signs must be parsed one at a time
            (r'[^\\\'"%{\n]+', ttype),
            (r'[\'"\\]', ttype),
            # unhandled string formatting sign
            (r'%|(\{{1,2})', ttype)
            # newlines are an error (use "nl" state)
        ]

    tokens = dict(
        root=[
            (r'^(@import)(.*)$', bygroups(Name.Decorator, Name.Namespace)),
            (r'#.*$', Comment),
            (r'^(rem|remark)v?(4|6)?( .*)$', bygroups(Name.Decorator, Name.Decorator, Number.Oct)),
            (ipv4_address, Number.Integer),
            (ipv6_address, Number.Integer),
            (r'(types? )([a-zA-Z0-9_,-]+)', bygroups(Name.Decorator, Number.Float)),
            # (r'type', Operator),
            include('builtins'),
            include('keywords'),
        ]
    )
    tokens['keywords'] = [
        (words(tuple(PyreParser.control_handlers.keys()), suffix=r'\b'), Name.Decorator),
    ]
    tokens['builtins'] = [
        (words(tuple(RuleParser.rule_handlers), prefix=r'(?<!\.)', suffix=r'\b'), Name.Builtin),
    ]

    tokens['numbers'] = [
        (r'(\d(?:_?\d)*\.(?:\d(?:_?\d)*)?|(?:\d(?:_?\d)*)?\.\d(?:_?\d)*)'
         r'([eE][+-]?\d(?:_?\d)*)?', Number.Float),
        (r'\d(?:_?\d)*[eE][+-]?\d(?:_?\d)*j?', Number.Float),
        (r'0[oO](?:_?[0-7])+', Number.Oct),
        (r'0[bB](?:_?[01])+', Number.Bin),
        (r'0[xX](?:_?[a-fA-F0-9])+', Number.Hex),
        (r'\d(?:_?\d)*', Number.Integer)
    ]
    tokens['backtick'] = []
    tokens['name'] = [
        (r'@\w+', Name.Decorator),
        (r'@', Operator),  # new matrix multiplication operator
        (uni_name, Name),
    ]




