"""logging.config.dictConfig — and why every line shows up twice

https://docs.python.org/3/howto/logging.html#configuring-logging

Ask for "add logging to this module" and the usual answer is
`logger.addHandler(logging.StreamHandler())` inside the module, often inside
a setup function. Three classic traps follow:

  1. The module logger has a handler *and* propagates to the root logger,
     which has one too: every record is printed twice.
  2. The setup function runs again (per request, per test): handlers pile up.
  3. Switching to dictConfig with the default `disable_existing_loggers=True`
     silently mutes every logger created before the call — usually the ones
     in imported modules.

Libraries should only call `getLogger(__name__)`. The application configures
logging once, at startup, in one dictConfig: handlers on the root logger,
child loggers only set levels and propagate, existing loggers stay enabled.
"""

import logging
import logging.config
import sys

FORMAT = "%(name)-8s %(levelname)-7s %(message)s"


def reset() -> None:
    """Forget all configuration between scenarios."""
    for name in ["", "app", "app.db", "vendor"]:
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        logger.disabled = False
        logger.propagate = True
        logger.setLevel(logging.NOTSET)


def stdout_handler() -> logging.Handler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(FORMAT))
    return handler


def setup_db_logging() -> logging.Logger:
    # What the module under review does on every call.
    logger = logging.getLogger("app.db")
    logger.addHandler(stdout_handler())
    logger.setLevel(logging.INFO)
    return logger


def trap_propagate() -> None:
    logging.getLogger().addHandler(stdout_handler())  # the application's root handler
    setup_db_logging().info("connected to primary")


def trap_repeated_setup() -> None:
    logging.getLogger().addHandler(stdout_handler())
    for _ in range(3):
        db = setup_db_logging()
    db.info("query took too long")


def trap_disable_existing() -> None:
    vendor = logging.getLogger("vendor")  # created at import time of a library
    logging.config.dictConfig({
        "version": 1,
        "formatters": {"plain": {"format": FORMAT}},
        "handlers": {"out": {"class": "logging.StreamHandler", "formatter": "plain",
                             "stream": "ext://sys.stdout"}},
        "root": {"handlers": ["out"], "level": "INFO"},
    })
    vendor.warning("certificate expires in 3 days")  # never printed
    logging.getLogger("main").info("started")  # created after dictConfig: works
    print(f"  (vendor logger disabled={vendor.disabled})")


CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": FORMAT}},
    "handlers": {"out": {"class": "logging.StreamHandler", "formatter": "plain",
                         "stream": "ext://sys.stdout"}},
    "root": {"handlers": ["out"], "level": "WARNING"},
    "loggers": {"app": {"level": "INFO"}, "app.db": {"level": "DEBUG"}},
}


def compliant() -> None:
    vendor = logging.getLogger("vendor")
    for _ in range(3):  # calling it again replaces, never accumulates
        logging.config.dictConfig(CONFIG)
    logging.getLogger("app.db").debug("connected to primary")
    logging.getLogger("app").info("started")
    logging.getLogger("app").debug("hidden: app is at INFO")
    vendor.warning("certificate expires in 3 days")
    vendor.info("hidden: root is at WARNING")
    print(f"  (handlers: root={len(logging.getLogger().handlers)}, "
          f"app.db={len(logging.getLogger('app.db').handlers)})")


def main() -> None:
    for title, scenario in [
        ("noncompliant: handler on child + root (propagate)", trap_propagate),
        ("noncompliant: setup called 3 times", trap_repeated_setup),
        ("noncompliant: dictConfig with default disable_existing_loggers", trap_disable_existing),
        ("compliant: one dictConfig, handlers on root only", compliant),
    ]:
        reset()
        print(title)
        scenario()


if __name__ == "__main__":
    main()

# Output:
# noncompliant: handler on child + root (propagate)
# app.db   INFO    connected to primary
# app.db   INFO    connected to primary
# noncompliant: setup called 3 times
# app.db   INFO    query took too long
# app.db   INFO    query took too long
# app.db   INFO    query took too long
# app.db   INFO    query took too long
# noncompliant: dictConfig with default disable_existing_loggers
# main     INFO    started
#   (vendor logger disabled=True)
# compliant: one dictConfig, handlers on root only
# app.db   DEBUG   connected to primary
# app      INFO    started
# vendor   WARNING certificate expires in 3 days
#   (handlers: root=1, app.db=0)
