"""Exception chaining — ``raise ... from err`` keeps the real cause

A common way to wrap a low-level error in a domain error is
``except KeyError: raise ConfigError("missing setting")``. Python still links
the two (``__context__``), but the traceback reads "During handling of the
above exception, another exception occurred", which tells the on-call engineer
the handler itself crashed. The other common variant, ``raise ConfigError(str(e))``
inside a helper, flattens the original type and traceback into a string.

Review note: when translating exceptions, write ``raise NewError(...) from
err`` so the cause is explicit ("The above exception was the direct cause").
Use ``from None`` only when the original is noise for the caller and contains
nothing sensitive or useful. Never drop the original by formatting it into a
message and raising outside the ``except`` block.
"""

import traceback


class ConfigError(Exception):
    pass


SETTINGS = {"db_host": "127.0.0.1"}


def get_noncompliant(key: str) -> str:
    try:
        return SETTINGS[key]
    except KeyError:
        raise ConfigError(f"missing setting {key!r}")


def get_compliant(key: str) -> str:
    try:
        return SETTINGS[key]
    except KeyError as err:
        raise ConfigError(f"missing setting {key!r}") from err


def get_hidden(key: str) -> str:
    try:
        return SETTINGS[key]
    except KeyError:
        raise ConfigError(f"missing setting {key!r}") from None


def summary(func) -> None:
    try:
        func("db_port")
    except ConfigError as exc:
        print(f"{func.__name__}: __cause__={exc.__cause__!r} "
              f"__context__={exc.__context__!r} suppress={exc.__suppress_context__}")
        # Keep only the unindented lines: exception lines and chaining banners.
        for line in "".join(traceback.format_exception(exc)).splitlines():
            if line and not line.startswith((" ", "Traceback")):
                print("   |", line)


def main() -> None:
    for func in (get_noncompliant, get_compliant, get_hidden):
        summary(func)


if __name__ == "__main__":
    main()

# Output:
# get_noncompliant: __cause__=None __context__=KeyError('db_port') suppress=False
#    | KeyError: 'db_port'
#    | During handling of the above exception, another exception occurred:
#    | ConfigError: missing setting 'db_port'
# get_compliant: __cause__=KeyError('db_port') __context__=KeyError('db_port') suppress=True
#    | KeyError: 'db_port'
#    | The above exception was the direct cause of the following exception:
#    | ConfigError: missing setting 'db_port'
# get_hidden: __cause__=None __context__=KeyError('db_port') suppress=True
#    | ConfigError: missing setting 'db_port'
