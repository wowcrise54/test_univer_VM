from __future__ import annotations

import argparse
import atexit
import copy
import contextlib
import contextvars
import hashlib
import json
import logging
import logging.handlers
import os
import queue
import re
import threading
import time
import traceback
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4 as _uuid4

import psycopg
import requests
from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[1] / ".env")


CHANNEL_FILES = {
    "app": "app.jsonl",
    "asset-card-build": "asset-card-build.jsonl",
    "mpvm-http": "mpvm-http.jsonl",
    "database": "database.jsonl",
    "frontend": "frontend.jsonl",
    "payloads": "debug-payloads.jsonl",
}
CONTEXT_FIELDS = ("trace_id", "request_id", "job_id", "asset_id", "stage")
SENSITIVE_KEY_PARTS = (
    "access_token",
    "accesstoken",
    "authorization",
    "client_secret",
    "clientsecret",
    "cookie",
    "password",
    "pdqltoken",
    "refresh_token",
    "refreshtoken",
    "secret",
    "sessionid",
    "timeline_token",
    "token",
)
REDACTED = "[REDACTED]"
MAX_LOG_STRING = 16_384
ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
URL_CREDENTIAL_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@:]+(?::[^\s/@]*)?@")
OPAQUE_PATH_SEGMENT = re.compile(r"^(?:[0-9a-fA-F-]{32,}|[A-Za-z0-9._~+=-]{40,})$")


@dataclass(frozen=True)
class DiagnosticsConfig:
    level: str
    log_dir: Path
    max_bytes: int
    backup_count: int
    retention_days: int
    debug_payloads: bool
    payload_max_bytes: int
    payload_retention_hours: int

    @classmethod
    def from_env(cls) -> "DiagnosticsConfig":
        return cls(
            level=os.getenv("MPVM_LOG_LEVEL", "INFO").strip().upper() or "INFO",
            log_dir=Path(os.getenv("MPVM_LOG_DIR", "output/logs")).expanduser().resolve(),
            max_bytes=_env_int("MPVM_LOG_MAX_BYTES", 100 * 1024 * 1024, 1024, 2**31 - 1),
            backup_count=_env_int("MPVM_LOG_BACKUP_COUNT", 10, 1, 100),
            retention_days=_env_int("MPVM_LOG_RETENTION_DAYS", 14, 1, 3650),
            debug_payloads=_env_bool("MPVM_DEBUG_PAYLOADS", False),
            payload_max_bytes=_env_int("MPVM_DEBUG_PAYLOAD_MAX_BYTES", 1024 * 1024, 256, 100 * 1024 * 1024),
            payload_retention_hours=_env_int("MPVM_DEBUG_PAYLOAD_RETENTION_HOURS", 24, 1, 8760),
        )


_trace_id = contextvars.ContextVar("diagnostic_trace_id", default=None)
_request_id = contextvars.ContextVar("diagnostic_request_id", default=None)
_job_id = contextvars.ContextVar("diagnostic_job_id", default=None)
_asset_id = contextvars.ContextVar("diagnostic_asset_id", default=None)
_stage = contextvars.ContextVar("diagnostic_stage", default=None)
_CONTEXT_VARS = {
    "trace_id": _trace_id,
    "request_id": _request_id,
    "job_id": _job_id,
    "asset_id": _asset_id,
    "stage": _stage,
}

_LOGGER = logging.getLogger("mpvm.diagnostics")
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.propagate = False
_CONFIG_LOCK = threading.RLock()
_CONFIG: DiagnosticsConfig | None = None
_LISTENER: logging.handlers.QueueListener | None = None
_QUEUE: queue.Queue[logging.LogRecord] | None = None
_OUTPUT_HANDLERS: list[logging.Handler] = []


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_trace_id() -> str:
    return _uuid4().hex


def normalize_correlation_id(value: Any, *, fallback: bool = True) -> str | None:
    text = str(value or "").strip()
    if text and ID_PATTERN.fullmatch(text):
        return text
    return new_trace_id() if fallback else None


def current_context() -> dict[str, Any]:
    return {
        name: value
        for name, variable in _CONTEXT_VARS.items()
        if (value := variable.get()) is not None
    }


def current_trace_id() -> str | None:
    return _trace_id.get()


def set_diagnostic_context(**values: Any) -> None:
    for name, value in values.items():
        variable = _CONTEXT_VARS.get(name)
        if variable is not None:
            variable.set(None if value is None else str(value))


@contextlib.contextmanager
def diagnostic_context(**values: Any):
    tokens: list[tuple[contextvars.ContextVar[Any], contextvars.Token[Any]]] = []
    try:
        for name, value in values.items():
            variable = _CONTEXT_VARS.get(name)
            if variable is not None and value is not None:
                tokens.append((variable, variable.set(str(value))))
        yield current_context()
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def _sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return any(re.sub(r"[^a-z0-9]", "", part) in normalized for part in SENSITIVE_KEY_PARTS)


def sanitize_text(value: str, *, max_length: int = MAX_LOG_STRING) -> str:
    text = BEARER_PATTERN.sub("Bearer [REDACTED]", value)
    text = URL_CREDENTIAL_PATTERN.sub(r"\1***:***@", text)
    for name in ("MPVM_PASSWORD", "MPVM_CLIENT_SECRET", "MPVM_ACCESS_TOKEN"):
        secret = os.getenv(name)
        if secret and len(secret) >= 4:
            text = text.replace(secret, REDACTED)
    if len(text) > max_length:
        return f"{text[:max_length]}...[TRUNCATED {len(text) - max_length} chars]"
    return text


def redact(value: Any, *, max_string: int = MAX_LOG_STRING, depth: int = 0) -> Any:
    if depth > 10:
        return "[MAX_DEPTH]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        return sanitize_text(value, max_length=max_string)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            result[key_text] = REDACTED if _sensitive_key(key_text) else redact(
                item, max_string=max_string, depth=depth + 1
            )
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item, max_string=max_string, depth=depth + 1) for item in value]
    return sanitize_text(str(value), max_length=max_string)


def sanitize_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        safe_segments = []
        for segment in parsed.path.split("/"):
            safe_segments.append("{id}" if OPAQUE_PATH_SEGMENT.fullmatch(segment) else segment)
        safe_query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            safe_query.append((key, REDACTED if _sensitive_key(key) else sanitize_text(value, max_length=256)))
        return urlunsplit((parsed.scheme, host, "/".join(safe_segments), urlencode(safe_query), ""))
    except Exception:
        return sanitize_text(url, max_length=1024)


class ChannelFilter(logging.Filter):
    def __init__(self, channel: str, *, errors_only: bool = False) -> None:
        super().__init__()
        self.channel = channel
        self.errors_only = errors_only

    def filter(self, record: logging.LogRecord) -> bool:
        if self.errors_only:
            return record.levelno >= logging.ERROR
        return getattr(record, "channel", "app") == self.channel


class JsonLinesFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "channel": getattr(record, "channel", "app"),
            "event": getattr(record, "event", record.getMessage()),
        }
        fields = getattr(record, "fields", {})
        if isinstance(fields, Mapping):
            payload.update(redact(fields))
        if record.exc_info:
            exc_type, exc_value, _tb = record.exc_info
            payload["exception"] = {
                "type": exc_type.__name__ if exc_type else None,
                "message": sanitize_text(str(exc_value)) if exc_value else None,
                "stack": sanitize_text("".join(traceback.format_exception(*record.exc_info)), max_length=128_000),
            }
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))


class PreservingQueueHandler(logging.handlers.QueueHandler):
    """QueueHandler for an in-process queue that keeps exc_info for JSON formatting."""

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        return copy.copy(record)


def configure_diagnostics(
    config: DiagnosticsConfig | None = None,
    *,
    force: bool = False,
) -> DiagnosticsConfig:
    global _CONFIG, _LISTENER, _QUEUE, _OUTPUT_HANDLERS
    with _CONFIG_LOCK:
        if _CONFIG is not None and not force:
            return _CONFIG
        if _LISTENER is not None:
            _LISTENER.stop()
            _LISTENER = None
        for handler in _OUTPUT_HANDLERS:
            handler.close()
        _OUTPUT_HANDLERS = []
        _LOGGER.handlers.clear()
        _CONFIG = config or DiagnosticsConfig.from_env()
        _CONFIG.log_dir.mkdir(parents=True, exist_ok=True)
        _cleanup_old_logs(_CONFIG)
        level = getattr(logging, _CONFIG.level, logging.INFO)
        formatter = JsonLinesFormatter()
        handlers: list[logging.Handler] = []
        for channel, filename in CHANNEL_FILES.items():
            handler = logging.handlers.RotatingFileHandler(
                _CONFIG.log_dir / filename,
                maxBytes=_CONFIG.max_bytes,
                backupCount=_CONFIG.backup_count,
                encoding="utf-8",
                delay=True,
            )
            handler.setLevel(level if channel != "payloads" else logging.DEBUG)
            handler.addFilter(ChannelFilter(channel))
            handler.setFormatter(formatter)
            handlers.append(handler)
        errors = logging.handlers.RotatingFileHandler(
            _CONFIG.log_dir / "errors.jsonl",
            maxBytes=_CONFIG.max_bytes,
            backupCount=_CONFIG.backup_count,
            encoding="utf-8",
            delay=True,
        )
        errors.setLevel(logging.ERROR)
        errors.addFilter(ChannelFilter("errors", errors_only=True))
        errors.setFormatter(formatter)
        handlers.append(errors)
        _QUEUE = queue.Queue()
        queue_handler = PreservingQueueHandler(_QUEUE)
        queue_handler.setLevel(logging.DEBUG)
        _LOGGER.addHandler(queue_handler)
        _OUTPUT_HANDLERS = handlers
        _LISTENER = logging.handlers.QueueListener(_QUEUE, *handlers, respect_handler_level=True)
        _LISTENER.start()
        return _CONFIG


def shutdown_diagnostics() -> None:
    global _CONFIG, _LISTENER, _QUEUE, _OUTPUT_HANDLERS
    with _CONFIG_LOCK:
        if _LISTENER is not None:
            _LISTENER.stop()
        for handler in _OUTPUT_HANDLERS:
            handler.close()
        _OUTPUT_HANDLERS = []
        _LISTENER = None
        _QUEUE = None
        _CONFIG = None
        _LOGGER.handlers.clear()


def flush_diagnostics(timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while _QUEUE is not None and not _QUEUE.empty() and time.monotonic() < deadline:
        time.sleep(0.01)


def _cleanup_old_logs(config: DiagnosticsConfig) -> None:
    now = datetime.now(timezone.utc)
    regular_cutoff = now - timedelta(days=config.retention_days)
    payload_cutoff = now - timedelta(hours=config.payload_retention_hours)
    for path in config.log_dir.glob("*.jsonl*"):
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            cutoff = payload_cutoff if path.name.startswith("debug-payloads") else regular_cutoff
            if modified < cutoff:
                path.unlink()
        except OSError:
            continue


def log_event(channel: str, event: str, *, level: int = logging.INFO, **fields: Any) -> None:
    if _CONFIG is None:
        configure_diagnostics()
    merged = {**current_context(), **{key: value for key, value in fields.items() if value is not None}}
    _LOGGER.log(level, event, extra={"channel": channel, "event": event, "fields": merged})


def log_exception(channel: str, event: str, **fields: Any) -> None:
    if _CONFIG is None:
        configure_diagnostics()
    merged = {**current_context(), **{key: value for key, value in fields.items() if value is not None}}
    _LOGGER.error(event, exc_info=True, extra={"channel": channel, "event": event, "fields": merged})


def capture_debug_payload(*, direction: str, payload: Any, **fields: Any) -> None:
    config = _CONFIG or configure_diagnostics()
    if not config.debug_payloads:
        return
    cleaned = redact(payload, max_string=config.payload_max_bytes)
    encoded = json.dumps(cleaned, ensure_ascii=False, default=str)
    truncated = len(encoded.encode("utf-8")) > config.payload_max_bytes
    if truncated:
        encoded = encoded.encode("utf-8")[: config.payload_max_bytes].decode("utf-8", errors="ignore")
        cleaned = {"truncated": True, "preview": encoded}
    log_event(
        "payloads",
        "payload.captured",
        level=logging.DEBUG,
        direction=direction,
        payload=cleaned,
        truncated=truncated,
        **fields,
    )


class DiagnosticSession(requests.Session):
    """Requests session that records sanitized MP VM request lifecycle events."""

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        remote_request_id = new_trace_id()
        endpoint = sanitize_url(url)
        safe_params = redact(kwargs.get("params") or {})
        started = time.perf_counter()
        log_event(
            "mpvm-http",
            "mpvm.request.started",
            level=logging.DEBUG,
            remote_request_id=remote_request_id,
            method=method.upper(),
            endpoint=endpoint,
            params=safe_params,
            timeout=kwargs.get("timeout"),
            worker=threading.current_thread().name,
        )
        capture_debug_payload(
            direction="request",
            payload=kwargs.get("json", kwargs.get("data")),
            remote_request_id=remote_request_id,
            method=method.upper(),
            endpoint=endpoint,
        )
        try:
            response = super().request(method, url, **kwargs)
        except Exception:
            log_exception(
                "mpvm-http",
                "mpvm.request.failed",
                remote_request_id=remote_request_id,
                method=method.upper(),
                endpoint=endpoint,
                params=safe_params,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                worker=threading.current_thread().name,
            )
            raise
        retry_history = getattr(getattr(response.raw, "retries", None), "history", ()) or ()
        response_bytes = _response_size(response)
        log_event(
            "mpvm-http",
            "mpvm.request.completed",
            level=logging.INFO if response.ok else logging.WARNING,
            remote_request_id=remote_request_id,
            method=method.upper(),
            endpoint=endpoint,
            params=safe_params,
            status=response.status_code,
            attempts=len(retry_history) + 1,
            retries=len(retry_history),
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            response_bytes=response_bytes,
            worker=threading.current_thread().name,
        )
        if not kwargs.get("stream"):
            content_type = response.headers.get("content-type", "")
            payload: Any = response.text
            if "json" in content_type:
                try:
                    payload = response.json()
                except ValueError:
                    pass
            capture_debug_payload(
                direction="response",
                payload=payload,
                remote_request_id=remote_request_id,
                method=method.upper(),
                endpoint=endpoint,
                status=response.status_code,
            )
        return response


def _response_size(response: requests.Response) -> int | None:
    header = response.headers.get("content-length")
    if header and header.isdigit():
        return int(header)
    try:
        return len(response.content)
    except Exception:
        return None


def describe_sql(query: Any) -> dict[str, str]:
    text = " ".join(str(query).split())
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]
    verb_match = re.match(r"(?i)^(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WITH)\b", text)
    table_match = re.search(r"(?i)\b(?:FROM|INTO|UPDATE|TABLE|JOIN)\s+([A-Za-z0-9_.\"]+)", text)
    verb = verb_match.group(1).upper() if verb_match else "SQL"
    table = table_match.group(1).strip('"') if table_match else "unknown"
    return {"operation": f"{verb} {table}", "sql_hash": digest}


class DiagnosticCursor(psycopg.Cursor[Any]):
    def execute(
        self,
        query: Any,
        params: Any = None,
        *,
        prepare: bool | None = None,
        binary: bool | None = None,
    ) -> "DiagnosticCursor":
        details = describe_sql(query)
        started = time.perf_counter()
        log_event("database", "db.query.started", level=logging.DEBUG, **details)
        try:
            result = super().execute(query, params, prepare=prepare, binary=binary)
        except Exception:
            log_exception(
                "database",
                "db.query.failed",
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                **details,
            )
            raise
        log_event(
            "database",
            "db.query.completed",
            level=logging.DEBUG,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            row_count=self.rowcount,
            **details,
        )
        return result  # type: ignore[return-value]

    def executemany(self, query: Any, params_seq: Iterable[Any], *, returning: bool = False) -> None:
        details = describe_sql(query)
        batch_size = len(params_seq) if hasattr(params_seq, "__len__") else None
        started = time.perf_counter()
        log_event("database", "db.batch.started", level=logging.DEBUG, batch_size=batch_size, **details)
        try:
            super().executemany(query, params_seq, returning=returning)
        except Exception:
            log_exception(
                "database",
                "db.batch.failed",
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                batch_size=batch_size,
                **details,
            )
            raise
        log_event(
            "database",
            "db.batch.completed",
            level=logging.DEBUG,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            batch_size=batch_size,
            row_count=self.rowcount,
            **details,
        )


class DiagnosticConnection(psycopg.Connection[Any]):
    def __exit__(self, exc_type: Any, exc_value: Any, traceback_value: Any) -> None:
        started = time.perf_counter()
        try:
            result = super().__exit__(exc_type, exc_value, traceback_value)
        except Exception:
            log_exception(
                "database",
                "db.transaction.failed",
                intended_action="rollback" if exc_type else "commit",
            )
            raise
        log_event(
            "database",
            "db.transaction.rollback" if exc_type else "db.transaction.commit",
            level=logging.WARNING if exc_type else logging.DEBUG,
            source="context_manager",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return result

    def commit(self) -> None:
        started = time.perf_counter()
        try:
            super().commit()
        except Exception:
            log_exception("database", "db.transaction.rollback", reason="commit_failed")
            raise
        log_event(
            "database",
            "db.transaction.commit",
            level=logging.DEBUG,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def rollback(self) -> None:
        started = time.perf_counter()
        try:
            super().rollback()
        finally:
            log_event(
                "database",
                "db.transaction.rollback",
                level=logging.WARNING,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )


def build_diagnostic_archive(
    *,
    trace_id: str | None = None,
    job_id: str | None = None,
    output_path: Path | None = None,
) -> Path:
    if not trace_id and not job_id:
        raise ValueError("trace_id or job_id is required")
    config = _CONFIG or configure_diagnostics()
    archive_dir = config.log_dir.parent / "diagnostics"
    archive_dir.mkdir(parents=True, exist_ok=True)
    identifier = trace_id or job_id or "unknown"
    output = output_path or archive_dir / f"diagnostic-{identifier}-{int(time.time())}.zip"
    events: list[str] = []
    counts: dict[str, int] = {}
    for path in sorted(config.log_dir.glob("*.jsonl*")):
        if not path.is_file():
            continue
        # errors.jsonl intentionally mirrors ERROR records from their source channel.
        if path.name.startswith("errors.jsonl"):
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as source:
                for line in source:
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if trace_id and event.get("trace_id") != trace_id:
                        continue
                    if job_id and event.get("job_id") != job_id:
                        continue
                    events.append(json.dumps(redact(event), ensure_ascii=False, separators=(",", ":")))
                    name = str(event.get("event") or "unknown")
                    counts[name] = counts.get(name, 0) + 1
        except OSError:
            continue
    manifest = {
        "created_at": utc_now(),
        "trace_id": trace_id,
        "job_id": job_id,
        "event_count": len(events),
        "event_counts": counts,
        "configuration": redact(asdict(config)),
    }
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, default=str))
        archive.writestr("events.jsonl", "\n".join(events) + ("\n" if events else ""))
    log_event(
        "app",
        "diagnostic.archive.created",
        trace_id=trace_id,
        job_id=job_id,
        output=str(output),
        event_count=len(events),
    )
    return output


def _main() -> int:
    parser = argparse.ArgumentParser(description="Build a sanitized MP VM diagnostic archive.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    bundle = subparsers.add_parser("bundle", help="Bundle logs by trace_id and/or job_id.")
    bundle.add_argument("--trace-id")
    bundle.add_argument("--job-id")
    bundle.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "bundle":
        path = build_diagnostic_archive(trace_id=args.trace_id, job_id=args.job_id, output_path=args.output)
        flush_diagnostics()
        print(path)
        return 0
    return 2


atexit.register(shutdown_diagnostics)


if __name__ == "__main__":
    raise SystemExit(_main())
