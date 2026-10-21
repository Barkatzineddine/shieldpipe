import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request

_logger = logging.getLogger("shieldpipe.audit")


class _StdoutHandler(logging.StreamHandler):
    """Resolves sys.stdout at write time instead of binding it once."""

    @property  # type: ignore[override]
    def stream(self):  # type: ignore[override]
        return sys.stdout

    @stream.setter
    def stream(self, _value) -> None:
        pass


def configure_audit_logging() -> None:
    """One JSON object per line on stdout, ready for a SIEM agent (Wazuh, Fluent Bit...)."""
    if _logger.handlers:
        return
    handler = _StdoutHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def audit(
    event: str,
    *,
    outcome: str,
    request: Request | None = None,
    actor: str | None = None,
    **fields: Any,
) -> None:
    """Never pass passwords or tokens here. Values are JSON-encoded, which neutralises
    newline-based log injection."""
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "type": "audit",
        "event": event,
        "outcome": outcome,
        "actor": actor,
    }
    if request is not None:
        record["src_ip"] = request.client.host if request.client else None
        record["method"] = request.method
        record["path"] = request.url.path
        record["request_id"] = getattr(request.state, "request_id", None)
    record.update(fields)
    _logger.info(json.dumps(record, default=str, ensure_ascii=False))
