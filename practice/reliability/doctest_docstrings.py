"""doctest — make docstring examples prove themselves

https://docs.python.org/3/library/doctest.html

It is easy to write beautiful docstrings with `>>>` examples. Nobody runs them,
and they are written *about* the code rather than *from* it: the example says
what the function was supposed to return, the code does something slightly
different, and a reader trusts the docstring. Edge cases ("0 bytes", bad
input) are where they drift first.

`doctest` executes every `>>>` line and compares the printed result. Run it in
CI (`python -m doctest -v module.py` or pytest `--doctest-modules`) and a wrong
example fails the build like any other test. Exceptions can be documented too:
only the `Traceback` header and the last line are compared. The demo uses a
custom runner so the report has no file paths in it.
"""

import doctest


def human_size(n: int) -> str:
    """Format a byte count with binary units.

    >>> human_size(0)
    '0 B'
    >>> human_size(1536)
    '1.5 KB'
    >>> human_size(5 * 1024 ** 3)
    '5.0 GiB'
    """
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(n)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")


def parse_duration(text: str) -> int:
    """Convert '1h30m', '45s', '2h' to seconds.

    >>> parse_duration("1h30m")
    5400
    >>> parse_duration("90")
    90
    >>> parse_duration("")
    0
    """
    total, number = 0, ""
    for ch in text:
        if ch.isdigit():
            number += ch
        elif ch in "hms" and number:
            total += int(number) * {"h": 3600, "m": 60, "s": 1}[ch]
            number = ""
        else:
            raise ValueError(f"bad duration: {text!r}")
    if number or not text:
        raise ValueError(f"bad duration: {text!r}")
    return total


def parse_duration_fixed(text: str) -> int:
    """Convert '1h30m', '45s', '2h' to seconds; a unit is required.

    >>> parse_duration_fixed("1h30m")
    5400
    >>> parse_duration_fixed("90")
    Traceback (most recent call last):
        ...
    ValueError: bad duration: '90'
    >>> parse_duration_fixed("")
    Traceback (most recent call last):
        ...
    ValueError: bad duration: ''
    """
    return parse_duration(text)


def human_size_fixed(n: int) -> str:
    """Format a byte count with binary units.

    >>> human_size_fixed(0)
    '0 B'
    >>> human_size_fixed(1536)
    '1.5 KiB'
    >>> [human_size_fixed(1024 ** p) for p in range(5)]  # doctest: +NORMALIZE_WHITESPACE
    ['1 B', '1.0 KiB', '1.0 MiB',
     '1.0 GiB', '1.0 TiB']
    """
    return human_size(n)


class QuietRunner(doctest.DocTestRunner):
    def __init__(self) -> None:
        super().__init__(verbose=False)
        self.lines: list[str] = []

    def report_failure(self, out, test, example, got) -> None:
        self.lines.append(f"  {test.name}: >>> {example.source.strip()}")
        self.lines.append(f"      documented: {example.want.strip()}")
        self.lines.append(f"      actual:     {got.strip()}")

    def report_unexpected_exception(self, out, test, example, exc_info) -> None:
        self.lines.append(f"  {test.name}: >>> {example.source.strip()}")
        self.lines.append(f"      documented: {example.want.strip()}")
        self.lines.append(f"      actual:     raised {exc_info[1]!r}")


def check(*functions) -> None:
    finder = doctest.DocTestFinder()
    runner = QuietRunner()
    for fn in functions:
        for test in finder.find(fn, fn.__name__, globs={fn.__name__: fn}):
            runner.run(test, out=lambda _: None)
    print(f"{', '.join(f.__name__ for f in functions)}: "
          f"{runner.tries} examples, {runner.failures} failed")
    for line in runner.lines:
        print(line)


def main() -> None:
    check(human_size, parse_duration)
    check(human_size_fixed, parse_duration_fixed)


if __name__ == "__main__":
    main()

# Output:
# human_size, parse_duration: 6 examples, 3 failed
#   human_size: >>> human_size(1536)
#       documented: '1.5 KB'
#       actual:     '1.5 KiB'
#   parse_duration: >>> parse_duration("90")
#       documented: 90
#       actual:     raised ValueError("bad duration: '90'")
#   parse_duration: >>> parse_duration("")
#       documented: 0
#       actual:     raised ValueError("bad duration: ''")
# human_size_fixed, parse_duration_fixed: 6 examples, 0 failed
