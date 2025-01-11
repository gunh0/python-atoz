"""Configuration from environment variables — parse once, validate, fail loudly

https://12factor.net/config

A common way to "read settings from the environment" is
`os.getenv("PORT", 8080)` scattered through the code. It looks fine and works
on the author's laptop, but every value from the environment is a *string*:
PORT becomes "8080" or "80800", DEBUG="false" is truthy, a typo in a variable
name silently falls back to the default, and the failure shows up hours later
deep inside a request handler. The reviewer should ask for one place that
reads the environment at startup, converts every value to its real type,
checks ranges and allowed values, reports *all* problems at once, and never
echoes secrets back into logs or error messages.
"""

from dataclasses import dataclass
from typing import Mapping


def noncompliant(env: Mapping[str, str]) -> dict:
    # The common idiom: defaults of the wrong type, no conversion.
    return {
        "port": env.get("APP_PORT", 8080),
        "debug": bool(env.get("APP_DEBUG", False)),
        "workers": env.get("APP_WORKERS", 4),
        "log_level": env.get("APP_LOG_LEVEL", "INFO"),
    }


class ConfigError(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off"}
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
KNOWN = {"APP_PORT", "APP_DEBUG", "APP_WORKERS", "APP_LOG_LEVEL", "APP_DB_PASSWORD"}


@dataclass(frozen=True)
class Settings:
    port: int
    debug: bool
    workers: int
    log_level: str
    db_password: str

    def __repr__(self) -> str:
        # Never let a secret reach a log line through repr().
        return (f"Settings(port={self.port}, debug={self.debug}, workers={self.workers}, "
                f"log_level={self.log_level!r}, db_password='***')")


def compliant(env: Mapping[str, str]) -> Settings:
    problems: list[str] = []

    def integer(name: str, default: int, lo: int, hi: int) -> int:
        raw = env.get(name)
        if raw is None:
            return default
        try:
            value = int(raw.strip())
        except ValueError:
            problems.append(f"{name}: not an integer: {raw!r}")
            return default
        if not lo <= value <= hi:
            problems.append(f"{name}: {value} outside {lo}..{hi}")
        return value

    def boolean(name: str, default: bool) -> bool:
        raw = env.get(name)
        if raw is None:
            return default
        if raw.strip().lower() in TRUE:
            return True
        if raw.strip().lower() in FALSE:
            return False
        problems.append(f"{name}: expected one of {sorted(TRUE | FALSE)}, got {raw!r}")
        return default

    def choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
        value = env.get(name, default).strip().upper()
        if value not in allowed:
            problems.append(f"{name}: {value!r} not in {list(allowed)}")
        return value

    def secret(name: str) -> str:
        value = env.get(name, "")
        if not value:
            problems.append(f"{name}: required and missing")  # value itself never printed
        return value

    # Typos like APP_WORKER are the classic silent fallback: flag unknown APP_ names.
    for name in sorted(k for k in env if k.startswith("APP_") and k not in KNOWN):
        problems.append(f"{name}: unknown setting (typo?)")

    settings = Settings(
        port=integer("APP_PORT", 8080, 1, 65535),
        debug=boolean("APP_DEBUG", False),
        workers=integer("APP_WORKERS", 4, 1, 64),
        log_level=choice("APP_LOG_LEVEL", "INFO", LEVELS),
        db_password=secret("APP_DB_PASSWORD"),
    )
    if problems:
        raise ConfigError(problems)
    return settings


def main() -> None:
    # A real program passes os.environ; fixed mappings keep the output stable.
    good = {"APP_PORT": "8443", "APP_DEBUG": "false", "APP_WORKERS": "8",
            "APP_DB_PASSWORD": "s3cr3t-from-vault", "HOME": "/home/app"}
    bad = {"APP_PORT": "80800", "APP_DEBUG": "flase", "APP_WORKER": "8",
           "APP_LOG_LEVEL": "verbose"}

    cfg = noncompliant(good)
    print(f"noncompliant: port={cfg['port']!r} debug={cfg['debug']!r} workers={cfg['workers']!r}")
    print(f"noncompliant: port + 1 -> {'TypeError' if isinstance(cfg['port'], str) else cfg['port'] + 1}")
    cfg = noncompliant(bad)
    print(f"noncompliant: bad env accepted -> port={cfg['port']!r} debug={cfg['debug']!r}")
    print()
    print(f"compliant:    {compliant(good)!r}")
    try:
        compliant(bad)
    except ConfigError as exc:
        print(f"compliant:    refused to start, {len(exc.problems)} problems:")
        for problem in exc.problems:
            print(f"  - {problem}")


if __name__ == "__main__":
    main()

# Output:
# noncompliant: port='8443' debug=True workers='8'
# noncompliant: port + 1 -> TypeError
# noncompliant: bad env accepted -> port='80800' debug=True
#
# compliant:    Settings(port=8443, debug=False, workers=8, log_level='INFO', db_password='***')
# compliant:    refused to start, 5 problems:
#   - APP_WORKER: unknown setting (typo?)
#   - APP_PORT: 80800 outside 1..65535
#   - APP_DEBUG: expected one of ['0', '1', 'false', 'no', 'off', 'on', 'true', 'yes'], got 'flase'
#   - APP_LOG_LEVEL: 'VERBOSE' not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']
#   - APP_DB_PASSWORD: required and missing
