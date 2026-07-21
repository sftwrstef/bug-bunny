from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import shlex
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


MAX_CURL_BYTES = 32 * 1024
MIN_MARKER_BYTES = 16
MAX_MARKER_BYTES = 512
MAX_RESPONSE_BYTES = 256 * 1024
MAX_REPLAY_REQUESTS = 4
CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 8

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SENSITIVE_QUERY_NAME = re.compile(
    r"(?i)(?:^|[_-])(?:auth|authorization|cookie|credential|jwt|key|password|secret|session|token)(?:$|[_-])"
)
_CREDENTIAL_HEADER_NAME = re.compile(
    r"(?i)(?:authorization|cookie|credential|csrf|xsrf|jwt|password|secret|session|token|api[-_]?key)"
)
_PRIMARY_CREDENTIAL_HEADER_NAME = re.compile(
    r"(?i)^(?:authorization|cookie|jwt|x-jwt|api[-_]?key|x-api[-_]?key|auth[-_]?token|x-auth[-_]?token|access[-_]?token|x-access[-_]?token|session[-_]?(?:id|token)|x-session[-_]?(?:id|token))$"
)
_SESSION_COOKIE_NAME = re.compile(
    r"(?i)(?:^|[-_.])(?:auth(?:entication)?|jwt|sess(?:ion)?(?:id)?|sid|token)(?:$|[-_.])"
)
_CSRF_NAME = re.compile(r"(?i)(?:^|[-_.])(?:csrf|xsrf)(?:$|[-_.])")
_AMBIGUOUS_ACCOUNT_HEADER_NAME = re.compile(
    r"(?i)(?:^|[-_])(?:account|actor|identity|member|principal|subject|tenant)(?:$|[-_](?:id|key|name|role|token)(?:$|[-_]))"
    r"|(?:^|[-_])user(?:$|[-_](?:email|id|key|name|role|token)(?:$|[-_]))"
    r"|(?:^|[-_])client[-_](?:id|key|secret|token)(?:$|[-_])"
    r"|(?:^|[-_])(?:request[-_])?signature(?:$|[-_])"
)
_SAFE_ACCOUNTISH_HEADERS = {"sec-fetch-user", "user-agent"}
_BLOCKED_HEADER_NAMES = {
    "accept-encoding",
    "connection",
    "content-length",
    "expect",
    "forwarded",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
}
_IGNORED_FLAGS = {
    "--compressed",
    "--globoff",
    "--http1.1",
    "--http2",
    "--show-error",
    "--silent",
    "-S",
    "-s",
}
_REJECTED_FLAGS = {
    "--cacert",
    "--capath",
    "--cert",
    "--connect-to",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--form",
    "--form-string",
    "--insecure",
    "--key",
    "--location",
    "--location-trusted",
    "--output",
    "--proxy",
    "--request-target",
    "--resolve",
    "--unix-socket",
    "--upload-file",
    "-F",
    "-L",
    "-T",
    "-d",
    "-k",
    "-o",
    "-x",
}


class ReplayValidationError(ValueError):
    """Safe validation error. Messages never contain captured values."""


class ReplayHostBusyError(ReplayValidationError):
    """Raised when another replay already owns the same process-local origin."""


_HOST_TRAFFIC_STATE_LOCK = threading.Lock()
_ACTIVE_REPLAY_ORIGINS: set[str] = set()
_LAST_REPLAY_REQUEST_AT: dict[str, float] = {}


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]

    def header_map(self) -> dict[str, str]:
        return {name: value for name, value in self.headers}


@dataclass(frozen=True)
class CapturePlan:
    owner: CapturedRequest
    peer: CapturedRequest
    credential_names: tuple[str, ...]
    endpoint_shape: dict[str, Any]
    capture_sha256: str
    pinned_ip: str
    external: bool


def _next(tokens: list[str], index: int, flag: str) -> tuple[str, int]:
    if index + 1 >= len(tokens):
        raise ReplayValidationError(f"{flag} requires a value.")
    return tokens[index + 1], index + 2


def _is_credential_header(name: str) -> bool:
    return bool(_CREDENTIAL_HEADER_NAME.search(name))


def _is_primary_credential_header(name: str) -> bool:
    return bool(_PRIMARY_CREDENTIAL_HEADER_NAME.fullmatch(name))


def _is_ambiguous_account_header(name: str) -> bool:
    return (
        name not in _SAFE_ACCOUNTISH_HEADERS
        and not _is_primary_credential_header(name)
        and bool(_AMBIGUOUS_ACCOUNT_HEADER_NAME.search(name))
    )


def _parse_header(raw_header: str) -> tuple[str, str]:
    if "\r" in raw_header or "\n" in raw_header or "\x00" in raw_header:
        raise ReplayValidationError("Captured headers cannot contain control characters.")
    if ":" not in raw_header:
        raise ReplayValidationError("Each captured header must use 'Name: value' syntax.")
    raw_name, raw_value = raw_header.split(":", 1)
    name = raw_name.strip().lower()
    value = raw_value.strip()
    if not _HEADER_NAME.fullmatch(name):
        raise ReplayValidationError("A captured header name is invalid.")
    if name in _BLOCKED_HEADER_NAMES or name.startswith("x-forwarded-") or name.startswith("proxy-"):
        raise ReplayValidationError(f"The captured {name} header is not replayable.")
    if _is_ambiguous_account_header(name):
        raise ReplayValidationError(
            "Captured requests cannot retain an ambiguous account-binding or signature header."
        )
    if not value:
        raise ReplayValidationError(f"The captured {name} header cannot be empty.")
    return name, value


def parse_curl_capture(raw: str) -> CapturedRequest:
    if not isinstance(raw, str) or not raw.strip():
        raise ReplayValidationError("Paste a DevTools Copy as cURL request.")
    if len(raw.encode("utf-8")) > MAX_CURL_BYTES:
        raise ReplayValidationError("A captured cURL request exceeds the 32 KiB limit.")
    if "\x00" in raw:
        raise ReplayValidationError("Captured cURL cannot contain null bytes.")
    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError as error:
        raise ReplayValidationError("Captured cURL quoting is invalid.") from error
    if not tokens or tokens[0] not in {"curl", "/usr/bin/curl"}:
        raise ReplayValidationError("The capture must start with curl.")

    method = "GET"
    url: str | None = None
    headers: dict[str, str] = {}
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in _IGNORED_FLAGS:
            index += 1
            continue
        if token in _REJECTED_FLAGS or any(token.startswith(f"{flag}=") for flag in _REJECTED_FLAGS if flag.startswith("--")):
            raise ReplayValidationError(f"The captured {token.split('=', 1)[0]} option is not allowed in read-only replay.")
        if token in {"-H", "--header"}:
            value, index = _next(tokens, index, token)
            name, header_value = _parse_header(value)
            headers[name] = header_value
            continue
        if token.startswith("--header="):
            name, header_value = _parse_header(token.split("=", 1)[1])
            headers[name] = header_value
            index += 1
            continue
        if token in {"-b", "--cookie"}:
            value, index = _next(tokens, index, token)
            name, header_value = _parse_header(f"Cookie: {value}")
            headers[name] = header_value
            continue
        if token.startswith("--cookie="):
            name, header_value = _parse_header(f"Cookie: {token.split('=', 1)[1]}")
            headers[name] = header_value
            index += 1
            continue
        if token in {"-A", "--user-agent"}:
            value, index = _next(tokens, index, token)
            name, header_value = _parse_header(f"User-Agent: {value}")
            headers[name] = header_value
            continue
        if token in {"-e", "--referer"}:
            value, index = _next(tokens, index, token)
            name, header_value = _parse_header(f"Referer: {value}")
            headers[name] = header_value
            continue
        if token in {"-X", "--request"}:
            value, index = _next(tokens, index, token)
            method = value.upper()
            continue
        if token.startswith("--request="):
            method = token.split("=", 1)[1].upper()
            index += 1
            continue
        if token == "--url":
            value, index = _next(tokens, index, token)
            if url is not None:
                raise ReplayValidationError("Capture exactly one URL per cURL request.")
            url = value
            continue
        if token.startswith("--url="):
            if url is not None:
                raise ReplayValidationError("Capture exactly one URL per cURL request.")
            url = token.split("=", 1)[1]
            index += 1
            continue
        if token.startswith("-"):
            raise ReplayValidationError(f"The captured {token.split('=', 1)[0]} option is not supported.")
        if url is not None:
            raise ReplayValidationError("Capture exactly one URL per cURL request.")
        url = token
        index += 1

    if method != "GET":
        raise ReplayValidationError("Authenticated replay currently permits GET only.")
    if url is None:
        raise ReplayValidationError("Captured cURL is missing its URL.")
    if len(headers) > 24:
        raise ReplayValidationError("Captured cURL exceeds the 24-header limit.")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ReplayValidationError("Captured URLs must use HTTP or HTTPS.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ReplayValidationError("Captured URLs cannot contain credentials or fragments.")
    try:
        parsed.port
    except ValueError as error:
        raise ReplayValidationError("Captured URL port is invalid.") from error
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if any(_SENSITIVE_QUERY_NAME.search(name) for name, _value in query_items):
        raise ReplayValidationError("Move session or token material out of the URL query before replay.")
    if len(url.encode("utf-8")) > 8192:
        raise ReplayValidationError("Captured URL exceeds the 8 KiB limit.")
    return CapturedRequest(method=method, url=url, headers=tuple(sorted(headers.items())))


def _default_port(parsed: Any) -> int:
    return parsed.port or (443 if parsed.scheme == "https" else 80)


def _origin(parsed: Any) -> tuple[str, str, int]:
    return parsed.scheme.lower(), str(parsed.hostname or "").lower().rstrip("."), _default_port(parsed)


def _derive_endpoint_shape(owner_url: str, peer_url: str) -> dict[str, Any]:
    owner = urlparse(owner_url)
    peer = urlparse(peer_url)
    if _origin(owner) != _origin(peer):
        raise ReplayValidationError("Account A and B captures must use the same exact origin.")

    owner_segments = owner.path.split("/")
    peer_segments = peer.path.split("/")
    if len(owner_segments) != len(peer_segments):
        raise ReplayValidationError("Account A and B captures must use matching endpoint shapes.")
    differences: list[tuple[str, int | str]] = []
    for index, (owner_value, peer_value) in enumerate(zip(owner_segments, peer_segments)):
        if owner_value != peer_value:
            differences.append(("path_segment", index))

    owner_query = parse_qsl(owner.query, keep_blank_values=True)
    peer_query = parse_qsl(peer.query, keep_blank_values=True)
    if [name for name, _value in owner_query] != [name for name, _value in peer_query]:
        raise ReplayValidationError("Account A and B captures must use matching query parameter names.")
    for index, ((name, owner_value), (_peer_name, peer_value)) in enumerate(zip(owner_query, peer_query)):
        if owner_value != peer_value:
            differences.append(("query_value", f"{name}:{index}"))
    if len(differences) != 1:
        raise ReplayValidationError("The two captures must differ by exactly one controlled object locator.")

    locator_kind, locator_position = differences[0]
    template_segments = list(owner_segments)
    template_query = [(name, "{OBJECT_ID}" if (locator_kind == "query_value" and locator_position == f"{name}:{index}") else "{VALUE}") for index, (name, _value) in enumerate(owner_query)]
    if locator_kind == "path_segment":
        template_segments[int(locator_position)] = "{OBJECT_ID}"
    safe_shape = {
        "scheme": owner.scheme.lower(),
        "hostname": str(owner.hostname or "").lower().rstrip("."),
        "port": _default_port(owner),
        "pathDepth": len([segment for segment in owner_segments if segment]),
        "locatorKind": locator_kind,
        "queryNames": [name for name, _value in owner_query],
    }
    template_material = urlunparse(
        (
            owner.scheme.lower(),
            f"{safe_shape['hostname']}:{safe_shape['port']}",
            "/".join(template_segments),
            "",
            urlencode(template_query),
            "",
        )
    )
    safe_shape["templateSha256"] = hashlib.sha256(template_material.encode("utf-8")).hexdigest()
    return safe_shape


def _cookie_primary_material(raw_cookie: str) -> tuple[tuple[str, str], ...]:
    parsed: list[tuple[str, str]] = []
    for raw_pair in raw_cookie.split(";"):
        pair = raw_pair.strip()
        if not pair or "=" not in pair:
            continue
        raw_name, value = pair.split("=", 1)
        name = raw_name.strip().lower()
        if not name or _CSRF_NAME.search(name):
            continue
        if _SESSION_COOKIE_NAME.search(name):
            parsed.append((f"cookie:{name}", value.strip()))
    return tuple(sorted(parsed))


def _session_fingerprint(
    request: CapturedRequest,
) -> tuple[tuple[str, ...], str, tuple[tuple[str, str], ...]]:
    credentials = [(name, value) for name, value in request.headers if _is_credential_header(name)]
    if not credentials:
        raise ReplayValidationError("Each capture must include Cookie, Authorization, or another session header.")
    primary_material: list[tuple[str, str]] = []
    for name, value in credentials:
        if name == "cookie":
            cookie_material = _cookie_primary_material(value)
            if not cookie_material:
                raise ReplayValidationError(
                    "Each Cookie capture must contain an identifiable session, auth, JWT, SID, or token cookie."
                )
            primary_material.extend(cookie_material)
        elif _is_primary_credential_header(name):
            primary_material.append((name, value))
    if not primary_material:
        raise ReplayValidationError(
            "Each capture must include a supported primary authentication credential."
        )
    names = tuple(name for name, _value in credentials)
    material = json.dumps(credentials, separators=(",", ":"), ensure_ascii=True)
    return names, hashlib.sha256(material.encode("utf-8")).hexdigest(), tuple(sorted(primary_material))


def _validate_distinct_primary_credentials(
    owner_primary: tuple[tuple[str, str], ...],
    peer_primary: tuple[tuple[str, str], ...],
) -> tuple[str, ...]:
    owner_names = tuple(name for name, _value in owner_primary)
    peer_names = tuple(name for name, _value in peer_primary)
    if owner_names != peer_names:
        raise ReplayValidationError(
            "Account A and B must use the same primary authentication credential names."
        )
    for (name, owner_value), (_peer_name, peer_value) in zip(owner_primary, peer_primary):
        owner_digest = hashlib.sha256(owner_value.encode("utf-8")).digest()
        peer_digest = hashlib.sha256(peer_value.encode("utf-8")).digest()
        if hmac.compare_digest(owner_digest, peer_digest):
            raise ReplayValidationError(
                "Account A and B must use distinct primary authentication credentials."
            )
    return owner_names


def _validate_resolution(hostname: str, port: int, external: bool) -> str:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ReplayValidationError("The captured hostname could not be resolved.") from error
    addresses: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in records:
        address = str(sockaddr[0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ReplayValidationError("The captured hostname did not resolve to an address.")
    parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
    if external:
        if not all(address.is_global for address in parsed_addresses):
            raise ReplayValidationError("External replay refuses private, loopback, link-local, or mixed DNS results.")
    elif not all(address.is_loopback for address in parsed_addresses):
        raise ReplayValidationError("Local replay is restricted to the exact loopback target.")
    return addresses[0]


def build_capture_plan(
    owner_curl: str,
    peer_curl: str,
    *,
    target_url: str,
    allowed_hosts: list[str] | None,
    external: bool,
) -> tuple[CapturePlan, dict[str, Any]]:
    owner = parse_curl_capture(owner_curl)
    peer = parse_curl_capture(peer_curl)
    owner_parsed = urlparse(owner.url)
    target_parsed = urlparse(target_url)
    endpoint_shape = _derive_endpoint_shape(owner.url, peer.url)
    scheme, hostname, port = _origin(owner_parsed)

    if external:
        normalized_hosts = {str(host).lower().rstrip(".") for host in (allowed_hosts or [])}
        if scheme != "https" or port != 443:
            raise ReplayValidationError("External authenticated replay requires HTTPS on port 443.")
        if hostname not in normalized_hosts:
            raise ReplayValidationError("Captured hostname is not in this run's explicit host allowlist.")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ReplayValidationError("External authenticated replay requires an allowlisted hostname, not an IP address.")
    elif _origin(owner_parsed) != _origin(target_parsed):
        raise ReplayValidationError("Local replay must use the exact origin recorded in the run.")

    owner_names, owner_fingerprint, owner_primary = _session_fingerprint(owner)
    peer_names, peer_fingerprint, peer_primary = _session_fingerprint(peer)
    if owner_names != peer_names:
        raise ReplayValidationError("Account A and B must use the same session-header names.")
    primary_credential_names = _validate_distinct_primary_credentials(owner_primary, peer_primary)
    if len(owner_names) > 6:
        raise ReplayValidationError("Authenticated replay accepts at most six session headers per actor.")

    pinned_ip = _validate_resolution(hostname, port, external)
    safe_material = {
        "method": owner.method,
        "endpointShape": endpoint_shape,
        "credentialHeaderNames": list(owner_names),
        "primaryCredentialNames": list(primary_credential_names),
        "ownerSessionSha256": owner_fingerprint,
        "peerSessionSha256": peer_fingerprint,
    }
    capture_sha256 = hashlib.sha256(
        json.dumps(safe_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    plan = CapturePlan(
        owner=owner,
        peer=peer,
        credential_names=owner_names,
        endpoint_shape=endpoint_shape,
        capture_sha256=capture_sha256,
        pinned_ip=pinned_ip,
        external=external,
    )
    preview = {
        "schemaVersion": 1,
        "method": owner.method,
        "origin": f"{scheme}://{hostname}" if port == (443 if scheme == "https" else 80) else f"{scheme}://{hostname}:{port}",
        "endpointShape": endpoint_shape,
        "credentialHeaderNames": list(owner_names),
        "primaryCredentialNames": list(primary_credential_names),
        "retainedHeaderNames": sorted(
            {name for name, _value in owner.headers + peer.headers if not _is_credential_header(name)}
        ),
        "sessionsDistinct": True,
        "ownerSessionFingerprint": owner_fingerprint[:12],
        "peerSessionFingerprint": peer_fingerprint[:12],
        "captureSha256": capture_sha256,
        "requestBudgetMax": MAX_REPLAY_REQUESTS,
        "redirectPolicy": "do-not-follow",
        "persistence": "sanitized receipt only; raw capture and response content remain ephemeral",
    }
    return plan, preview


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str) -> None:
        super().__init__(host, port=port, timeout=CONNECT_TIMEOUT_SECONDS)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str) -> None:
        super().__init__(host, port=port, timeout=CONNECT_TIMEOUT_SECONDS, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _replay_origin_key(plan: CapturePlan) -> str:
    return (
        f"{plan.endpoint_shape['scheme']}://"
        f"{plan.endpoint_shape['hostname']}:{plan.endpoint_shape['port']}"
    )


@contextmanager
def _reserve_replay_origin(origin_key: str) -> Any:
    with _HOST_TRAFFIC_STATE_LOCK:
        if origin_key in _ACTIVE_REPLAY_ORIGINS:
            raise ReplayHostBusyError(
                "Another authenticated replay is already active for this exact origin."
            )
        _ACTIVE_REPLAY_ORIGINS.add(origin_key)
    try:
        yield
    finally:
        with _HOST_TRAFFIC_STATE_LOCK:
            _ACTIVE_REPLAY_ORIGINS.discard(origin_key)


def _pace_replay_origin(origin_key: str, pace_seconds: float) -> None:
    with _HOST_TRAFFIC_STATE_LOCK:
        previous_start = _LAST_REPLAY_REQUEST_AT.get(origin_key, 0.0)
    wait_for = pace_seconds - (time.monotonic() - previous_start)
    if wait_for > 0:
        time.sleep(wait_for)
    with _HOST_TRAFFIC_STATE_LOCK:
        _LAST_REPLAY_REQUEST_AT[origin_key] = time.monotonic()


def _headers_for(request: CapturedRequest, replacement_credentials: CapturedRequest | None = None) -> dict[str, str]:
    headers = {
        name: value
        for name, value in request.headers
        if not _is_credential_header(name)
    }
    source = replacement_credentials or request
    headers.update({name: value for name, value in source.headers if _is_credential_header(name)})
    headers["accept-encoding"] = "identity"
    headers["connection"] = "close"
    headers.setdefault("user-agent", "ControlX/0.3 authenticated-replay")
    return headers


def _request_once(
    request: CapturedRequest,
    *,
    marker: str,
    unexpected_marker: str,
    pinned_ip: str,
    replacement_credentials: CapturedRequest | None = None,
) -> dict[str, Any]:
    parsed = urlparse(request.url)
    port = _default_port(parsed)
    connection_class = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    connection = connection_class(str(parsed.hostname), port, pinned_ip)
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"
    started = time.monotonic()
    response_status: int | None = None
    try:
        connection.request(request.method, target, headers=_headers_for(request, replacement_credentials))
        if connection.sock is not None:
            connection.sock.settimeout(READ_TIMEOUT_SECONDS)
        response = connection.getresponse()
        response_status = response.status
        content_encoding = str(response.getheader("content-encoding") or "identity").lower()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        if len(body) > MAX_RESPONSE_BYTES:
            return {
                "status": response_status,
                "outcome": "response_limit",
                "bytes": MAX_RESPONSE_BYTES,
                "elapsedMs": elapsed_ms,
                "responseSha256": None,
                "markerObserved": False,
                "unexpectedMarkerObserved": False,
            }
        if content_encoding not in {"", "identity"}:
            return {
                "status": response_status,
                "outcome": "unsupported_encoding",
                "bytes": len(body),
                "elapsedMs": elapsed_ms,
                "responseSha256": hashlib.sha256(body).hexdigest(),
                "markerObserved": False,
                "unexpectedMarkerObserved": False,
            }
        marker_observed = marker.encode("utf-8") in body
        unexpected_marker_observed = unexpected_marker.encode("utf-8") in body
        if 300 <= response_status < 400:
            outcome = "redirect_blocked"
        elif response_status == 429:
            outcome = "rate_limited"
        elif response_status >= 500:
            outcome = "server_error"
        else:
            outcome = "response"
        return {
            "status": response_status,
            "outcome": outcome,
            "bytes": len(body),
            "elapsedMs": elapsed_ms,
            "responseSha256": hashlib.sha256(body).hexdigest(),
            "markerObserved": marker_observed,
            "unexpectedMarkerObserved": unexpected_marker_observed,
        }
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
        return {
            "status": response_status,
            "outcome": "transport_error",
            "bytes": 0,
            "elapsedMs": round((time.monotonic() - started) * 1000),
            "responseSha256": None,
            "markerObserved": False,
            "unexpectedMarkerObserved": False,
        }
    finally:
        connection.close()


def _control_passed(attempt: dict[str, Any]) -> bool:
    status = attempt.get("status")
    return (
        attempt.get("outcome") == "response"
        and isinstance(status, int)
        and 200 <= status < 300
        and attempt.get("markerObserved") is True
        and attempt.get("unexpectedMarkerObserved") is False
    )


def execute_capture_plan(
    plan: CapturePlan,
    *,
    owner_marker: str,
    peer_marker: str,
    requests_per_second: int = 1,
) -> dict[str, Any]:
    for marker in (owner_marker, peer_marker):
        marker_bytes = marker.encode("utf-8")
        if marker != marker.strip() or not marker:
            raise ReplayValidationError("Each benign marker must be non-empty with no surrounding whitespace.")
        if not MIN_MARKER_BYTES <= len(marker_bytes) <= MAX_MARKER_BYTES:
            raise ReplayValidationError("Each benign marker must contain 16–512 UTF-8 bytes.")
        if len(set(marker.casefold())) < 8 or not any(character.isalpha() for character in marker) or not any(character.isdigit() for character in marker):
            raise ReplayValidationError(
                "Each benign marker must be a high-entropy sentinel containing letters, digits, and at least eight distinct characters."
            )
    folded_owner_marker = owner_marker.casefold()
    folded_peer_marker = peer_marker.casefold()
    if folded_owner_marker in folded_peer_marker or folded_peer_marker in folded_owner_marker:
        raise ReplayValidationError("Account A and B markers must be distinct and non-overlapping.")
    raw_request_material = "\n".join(
        [plan.owner.url, plan.peer.url]
        + [value for _name, value in plan.owner.headers]
        + [value for _name, value in plan.peer.headers]
    )
    if owner_marker in raw_request_material or peer_marker in raw_request_material:
        raise ReplayValidationError("A benign response marker cannot appear in a captured request.")

    pace_seconds = 1 / max(1, min(int(requests_per_second or 1), 2))
    attempts: list[dict[str, Any]] = []
    origin_key = _replay_origin_key(plan)

    def run(
        branch: str,
        request: CapturedRequest,
        marker: str,
        unexpected_marker: str,
        replacement: CapturedRequest | None = None,
    ) -> dict[str, Any]:
        _pace_replay_origin(origin_key, pace_seconds)
        result = _request_once(
            request,
            marker=marker,
            unexpected_marker=unexpected_marker,
            pinned_ip=plan.pinned_ip,
            replacement_credentials=replacement,
        )
        result = {"sequence": len(attempts) + 1, "branch": branch, **result}
        attempts.append(result)
        return result

    with _reserve_replay_origin(origin_key):
        peer_control = run("peer_control", plan.peer, peer_marker, owner_marker)
        owner_control = run("owner_control", plan.owner, owner_marker, peer_marker)

        if not _control_passed(peer_control) or not _control_passed(owner_control):
            verdict = "INCONCLUSIVE"
            classification = "CONTROL_FAILED"
            reason = "At least one same-account control failed or contained the other actor's marker, so the cross-account hypothesis was not tested."
        else:
            first_replay = run("cross_account_replay", plan.owner, owner_marker, peer_marker, plan.peer)
            if (
                first_replay["markerObserved"] is True
                and first_replay["unexpectedMarkerObserved"] is False
                and first_replay["outcome"] == "response"
            ):
                verdict = "VERIFIED"
                classification = "CROSS_ACCOUNT_OBJECT_EXPOSURE"
                reason = "Account B's isolated session retrieved Account A's unique controlled marker."
            elif first_replay["outcome"] != "response" or first_replay["unexpectedMarkerObserved"] is True:
                verdict = "INCONCLUSIVE"
                classification = "UNSTABLE_REPLAY"
                reason = "The cross-account replay hit a network boundary or returned the peer control marker unexpectedly."
            else:
                second_replay = run(
                    "cross_account_replay_repeat",
                    plan.owner,
                    owner_marker,
                    peer_marker,
                    plan.peer,
                )
                stable = (
                    second_replay["outcome"] == "response"
                    and second_replay["markerObserved"] is False
                    and second_replay["unexpectedMarkerObserved"] is False
                    and first_replay["unexpectedMarkerObserved"] is False
                    and second_replay["status"] == first_replay["status"]
                )
                if stable:
                    verdict = "INVALID"
                    classification = "NO_CROSS_ACCOUNT_EXPOSURE"
                    reason = "Both sessions passed their controls and Account B was denied Account A's marker twice."
                else:
                    verdict = "INCONCLUSIVE"
                    classification = "UNSTABLE_REPLAY"
                    reason = "The two cross-account outcomes were inconsistent or incomplete."

    return {
        "schemaVersion": 1,
        "verdict": verdict,
        "classification": classification,
        "submissionReady": False,
        "reason": reason,
        "requestBudgetUsed": len(attempts),
        "requestBudgetMax": MAX_REPLAY_REQUESTS,
        "markerNegativeControls": True,
        "attempts": attempts,
    }


def build_sanitized_artifact(
    *,
    run_id: str,
    plan: CapturePlan,
    execution: dict[str, Any],
    recorded_at: str,
    object_kind: str,
) -> dict[str, Any]:
    result = {
        **execution,
        "recordedAt": recorded_at,
        "objectKind": object_kind,
        "captureSha256": plan.capture_sha256,
        "endpointShape": plan.endpoint_shape,
        "hostname": plan.endpoint_shape["hostname"],
        "method": plan.owner.method,
        "credentialHeaderNames": list(plan.credential_names),
        "networkBoundary": {
            "dnsPinned": True,
            "redirectsFollowed": 0,
            "freshConnectionPerAttempt": True,
            "responseBytesPerAttemptMax": MAX_RESPONSE_BYTES,
        },
        "redaction": {
            "rawCurlAbsent": True,
            "rawUrlsAbsent": True,
            "objectLocatorsAbsent": True,
            "requestBodiesAbsent": True,
            "responseBodiesAbsent": True,
            "headerValuesAbsent": True,
            "credentialsAbsent": True,
            "markersAbsent": True,
            "cookiesAndTokensAbsent": True,
            "emailAddressesAbsent": True,
        },
    }
    core = {
        "schema_version": 1,
        "proof_type": "authenticated_capture_replay",
        "evidence_origin": "ephemeral_curl_capture",
        "run_id": run_id,
        "recorded_at": recorded_at,
        "result": result,
    }
    integrity = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**core, "integrity_sha256": integrity}


def validate_sanitized_artifact(payload: Any, *, run_id: str, allowed_hosts: list[str]) -> bool:
    try:
        if set(payload) != {
            "schema_version", "proof_type", "evidence_origin", "run_id", "recorded_at", "result", "integrity_sha256"
        }:
            return False
        if payload["schema_version"] != 1 or payload["proof_type"] != "authenticated_capture_replay":
            return False
        if payload["evidence_origin"] != "ephemeral_curl_capture" or payload["run_id"] != run_id:
            return False
        integrity = payload["integrity_sha256"]
        core = {key: value for key, value in payload.items() if key != "integrity_sha256"}
        expected = hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if not isinstance(integrity, str) or not hmac.compare_digest(integrity, expected):
            return False
        result = payload["result"]
        if result["verdict"] not in {"VERIFIED", "INVALID", "INCONCLUSIVE"}:
            return False
        expected_classifications = {
            "VERIFIED": "CROSS_ACCOUNT_OBJECT_EXPOSURE",
            "INVALID": "NO_CROSS_ACCOUNT_EXPOSURE",
            "INCONCLUSIVE": {"CONTROL_FAILED", "UNSTABLE_REPLAY"},
        }
        expected_classification = expected_classifications[result["verdict"]]
        if isinstance(expected_classification, set):
            if result["classification"] not in expected_classification:
                return False
        elif result["classification"] != expected_classification:
            return False
        if result["submissionReady"] is not False:
            return False
        if result.get("markerNegativeControls") is not True:
            return False
        if result["hostname"] not in {host.lower().rstrip(".") for host in allowed_hosts}:
            return False
        if result["method"] != "GET" or result["requestBudgetMax"] != MAX_REPLAY_REQUESTS:
            return False
        attempts = result["attempts"]
        if not isinstance(attempts, list) or len(attempts) != result["requestBudgetUsed"] or not 2 <= len(attempts) <= 4:
            return False
        if any(
            set(attempt)
            != {
                "sequence",
                "branch",
                "status",
                "outcome",
                "bytes",
                "elapsedMs",
                "responseSha256",
                "markerObserved",
                "unexpectedMarkerObserved",
            }
            for attempt in attempts
        ):
            return False
        if any(attempt["sequence"] != index + 1 for index, attempt in enumerate(attempts)):
            return False
        redaction = result["redaction"]
        if not isinstance(redaction, dict) or not redaction or not all(value is True for value in redaction.values()):
            return False
        return True
    except (KeyError, TypeError, ValueError):
        return False
