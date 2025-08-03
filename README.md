# python-atoz

My Python study notes as runnable code: system administration, secure coding, and the pitfalls I keep running into in practice. Part of the *-atoz series next to [java-atoz](https://github.com/gunh0/java-atoz) and [kotlin-atoz](https://github.com/gunh0/kotlin-atoz).

| Section | Examples | |
| --- | ---: | --- |
| [`sysadmin/`](sysadmin/README.md) | 18 | Server and network operations: inventory, logs, RAID/IPMI/SNMP output, interface counters, scheduling. |
| [`security/`](security/README.md) | 23 | Secure coding with the standard library: injection, files, web input, parsing, crypto, auth, secrets, supply chain. |
| `practice/` | 17 | Language pitfalls, data handling, concurrency, reliability and code review checks. |
| [`Fluent/`](Fluent/README.md) | notebooks | Reading notes for *Fluent Python* |
| [`HighPerformance/`](HighPerformance/README.md) | notebooks | Reading notes for *High Performance Python* |

## How the examples work

Every example is one file that runs on its own and ends with an `# Output:` block — the exact output it prints. `scripts/check.py` runs each file and fails when the real output differs, and CI runs it on Python 3.13. Only the standard library is used, and anything that would touch a real device or the network uses embedded sample data or `127.0.0.1`.

```bash
python3 scripts/check.py      # all examples
make check
```

Examples that need a newer interpreter start with `# requires-python: >=3.x` and are skipped on older versions.

## Setup for the notebooks

```bash
python3 -m venv ./venv
source venv/bin/activate
pip install -r requirements.txt
```
