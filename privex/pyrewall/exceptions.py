class PyreException(Exception):
    pass


class RuleSyntaxError(PyreException):
    pass


class UnknownKeyword(RuleSyntaxError):
    """Raised when there's no known Control Directive / Rule Keyword handler available for a given line"""
    pass


class InvalidPort(PyreException):
    pass


class IPTablesError(PyreException):
    pass


class ReturnCodeError(PyreException):
    pass

