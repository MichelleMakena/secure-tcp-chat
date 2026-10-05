"""Secure, non-blocking logging for the TCP chat application.

The logging design uses QueueHandler and QueueListener so worker threads do not
block while writing to disk. Log files rotate automatically and a redaction
filter prevents accidental recording of private keys, RSA prime values or
plaintext session keys.
"""
from __future__ import annotations

import atexit
import logging
import logging.handlers
import queue
import re
import sys
import threading
from pathlib import Path
from typing import Optional

_LISTENERS: dict[str, logging.handlers.QueueListener] = {}
_LOG_PATHS: dict[str, Path] = {}
_LOCK = threading.Lock()


class SensitiveDataFilter(logging.Filter):
    """Redact key material while preserving non-secret fingerprints."""

    PRIVATE_PEM = re.compile(
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    )
    NAMED_SECRET = re.compile(
        r"(?i)\b(?:private[_ -]?key|session[_ -]?key|plaintext[_ -]?aes[_ -]?key|"
        r"rsa[_ -]?prime[_ -]?[pq]|prime[_ -]?[pq])\s*[:=]\s*([^\s,;]+)"
    )
    RSA_PARAMETER = re.compile(r"(?i)(?<![A-Za-z])(?:p|q|d)\s*=\s*([0-9]{8,})")

    @classmethod
    def redact(cls, value: object) -> str:
        text = str(value)
        text = cls.PRIVATE_PEM.sub("[REDACTED PRIVATE KEY]", text)
        text = cls.NAMED_SECRET.sub(lambda m: m.group(0).split(":")[0].split("=")[0] + "=[REDACTED]", text)
        text = cls.RSA_PARAMETER.sub(lambda m: m.group(0).split("=")[0] + "=[REDACTED]", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = self.redact(rendered)
        record.args = ()
        return True


def configure_secure_logger(
    role_name: str,
    log_directory: str | Path = "logs",
    max_bytes: int = 1_000_000,
    backup_count: int = 5,
) -> tuple[logging.Logger, Path]:
    """Create one rotating, asynchronous logger for Alice or Bob."""
    safe_role = re.sub(r"[^A-Za-z0-9_-]+", "_", role_name.strip() or "application").lower()
    logger_name = f"secure_chat.{safe_role}"

    with _LOCK:
        existing = logging.getLogger(logger_name)
        if logger_name in _LISTENERS:
            return existing, _LOG_PATHS[logger_name]

        directory = Path(log_directory).expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True)
        log_path = directory / f"{safe_role}_secure_chat.log"

        log_queue: queue.Queue[logging.LogRecord] = queue.Queue()
        queue_handler = logging.handlers.QueueHandler(log_queue)
        queue_handler.addFilter(SensitiveDataFilter())

        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.INFO)
        file_handler.addFilter(SensitiveDataFilter())
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()
        logger.addHandler(queue_handler)
        logger.propagate = False

        listener = logging.handlers.QueueListener(log_queue, file_handler, respect_handler_level=True)
        listener.start()
        _LISTENERS[logger_name] = listener
        _LOG_PATHS[logger_name] = log_path

        logger.info("APPLICATION_START | role=%s | persistent_log=%s", role_name, log_path)
        logger.info(
            "LOGGING_POLICY | Private keys, RSA prime factors, plaintext AES keys and chat plaintext are not logged."
        )
        return logger, log_path


def friendly_error_message(error: BaseException) -> str:
    """Convert technical exceptions into concise user-facing messages."""
    if isinstance(error, ConnectionRefusedError):
        return "Connection refused. Start Alice's server before connecting Bob."
    if isinstance(error, TimeoutError):
        return "The peer did not respond before the operation timed out."
    if isinstance(error, PermissionError):
        return "Permission was denied while accessing a file or network resource."
    if isinstance(error, FileNotFoundError):
        return "The selected file could not be found."
    if isinstance(error, OSError):
        return f"A network or operating-system error occurred: {error}"
    return str(error) or error.__class__.__name__


def install_exception_hooks(logger: logging.Logger) -> None:
    """Record otherwise-unhandled main-thread and worker-thread exceptions."""
    def thread_hook(args: threading.ExceptHookArgs) -> None:
        logger.critical(
            "UNHANDLED_THREAD_EXCEPTION | thread=%s",
            args.thread.name if args.thread else "unknown",
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    def system_hook(exc_type: type[BaseException], exc_value: BaseException, exc_traceback) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logger.critical(
            "UNHANDLED_MAIN_EXCEPTION",
            exc_info=(exc_type, exc_value, exc_traceback),
        )

    threading.excepthook = thread_hook
    sys.excepthook = system_hook


def flush_secure_logs() -> None:
    """Wait briefly for queued records and flush file handlers."""
    with _LOCK:
        listeners = list(_LISTENERS.values())
    for listener in listeners:
        try:
            listener.queue.join()
        except Exception:
            pass
        for handler in getattr(listener, "handlers", ()):  # type: ignore[attr-defined]
            try:
                handler.flush()
            except Exception:
                pass


def shutdown_secure_logging() -> None:
    """Stop all listener threads safely at application exit."""
    with _LOCK:
        items = list(_LISTENERS.items())
        _LISTENERS.clear()
        _LOG_PATHS.clear()
    for _name, listener in items:
        try:
            listener.stop()
        except Exception:
            pass


atexit.register(shutdown_secure_logging)
