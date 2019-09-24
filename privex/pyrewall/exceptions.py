class PyreException(Exception):
    pass


class RuleSyntaxError(PyreException):
    pass


class InvalidPort(PyreException):
    pass