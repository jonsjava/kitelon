import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

INSTALL_DIR = Path(os.environ.get("KITELON_INSTALL_DIR", "/usr/share/kitelon"))
DEFAULT_LOG_DIR = Path("/var/log/kitelon")
FALLBACK_LOG_DIR = INSTALL_DIR / "logs"

_LOGGERS: dict[str, logging.Logger] = {}


def _truthy(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


def logging_enabled() -> bool:
    return _truthy(os.environ.get("LOG_ENABLED"), default=True)


def log_dir() -> Path:
    raw = os.environ.get("LOG_DIR") or os.environ.get("KITELON_LOG_DIR")
    if raw:
        return Path(raw)
    return DEFAULT_LOG_DIR


def log_level_name() -> str:
    return (os.environ.get("LOG_LEVEL") or "INFO").upper()


def _resolve_log_dir() -> Path:
    preferred = log_dir()
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        test_file = preferred / ".write_test"
        test_file.write_text("", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return preferred
    except OSError:
        fallback = FALLBACK_LOG_DIR
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def get_logger(component: str) -> logging.Logger:
    """Return a rotating-file logger: kitelon.<component> → <LOG_DIR>/<component>.log."""
    name = f"kitelon.{component}"
    if name in _LOGGERS:
        return _LOGGERS[name]

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level_name(), logging.INFO))
    logger.propagate = False

    if logging_enabled():
        directory = _resolve_log_dir()
        max_bytes = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
        backup_count = int(os.environ.get("LOG_BACKUP_COUNT", "5"))
        handler = RotatingFileHandler(
            directory / f"{component}.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)

    if _truthy(os.environ.get("LOG_STDERR", "1"), default=True):
        stderr = logging.StreamHandler(sys.stderr)
        stderr.setFormatter(logging.Formatter(f"[kitelon-{component}] %(message)s"))
        logger.addHandler(stderr)

    _LOGGERS[name] = logger
    return logger


def log_message(component: str, message: str, *, level: int = logging.INFO) -> None:
    get_logger(component).log(level, message)
