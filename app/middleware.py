import json
import re
import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS = {
    # JSON-only API: nothing should ever render, frame or load resources from it.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}

_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class _BodyTooLargeError(Exception):
    pass


class SecurityMiddleware:
    """Pure ASGI middleware: request IDs, security headers and a request body size cap.

    Written at the ASGI level so it also covers error responses and streamed bodies
    without a Content-Length header.
    """

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = self._request_id(scope)
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                headers["X-Request-ID"] = request_id
            await send(message)

        declared = self._content_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            await self._reject(send_with_headers)
            return

        received = 0
        too_large = False
        rejected = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    too_large = True
                    raise _BodyTooLargeError
            return message

        async def guarded_send(message: Message) -> None:
            # Frameworks may catch the receive error and answer 400 themselves;
            # swap whatever they send for a 413.
            nonlocal rejected
            if not too_large:
                await send_with_headers(message)
                return
            if message["type"] == "http.response.start" and not rejected:
                rejected = True
                await self._reject(send_with_headers)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLargeError:
            if not rejected:
                await self._reject(send_with_headers)

    @staticmethod
    def _request_id(scope: Scope) -> str:
        for name, value in scope["headers"]:
            if name == b"x-request-id":
                candidate = value.decode("latin-1")
                if _REQUEST_ID.match(candidate):
                    return candidate
        return str(uuid.uuid4())

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps({"detail": "Request body too large"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
