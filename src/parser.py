from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit


VLESS_RE = re.compile(r"vless://[^\s<>\"']+", re.IGNORECASE)
TRAILING_CHARS = ".,;:!?)]}"


@dataclass
class VlessNode:
    uri: str
    uuid: str
    host: str
    port: int
    params: dict[str, str]
    name: str
    source: str
    sources: list[str] = field(default_factory=list)
    latency_ms: float | None = None
    country: str = "ZZ"
    exit_ip: str | None = None

    def __post_init__(self) -> None:
        if not self.sources:
            self.sources = [self.source]


def _extract_uris(text: str) -> list[str]:
    return [match.group(0).rstrip(TRAILING_CHARS) for match in VLESS_RE.finditer(text)]


def _decode_base64(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 16 or re.search(r"[^A-Za-z0-9_+\-/=]", compact):
        return None

    padded = compact + "=" * (-len(compact) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error):
        return None
    return decoded.decode("utf-8", errors="replace")


def extract_vless(text: str) -> list[str]:
    found = _extract_uris(text)
    decoded = _decode_base64(text)
    if decoded:
        found.extend(_extract_uris(decoded))

    unique: list[str] = []
    seen: set[str] = set()
    for uri in found:
        if uri not in seen:
            seen.add(uri)
            unique.append(uri)
    return unique


def parse_vless(uri: str, source: str) -> VlessNode | None:
    try:
        parsed = urlsplit(uri)
        if parsed.scheme.lower() != "vless" or not parsed.username or not parsed.hostname:
            return None
        if parsed.port is None or not 1 <= parsed.port <= 65535:
            return None
    except ValueError:
        return None

    params = {
        key.lower(): values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }
    name = unquote(parsed.fragment).strip()
    return VlessNode(
        uri=uri,
        uuid=unquote(parsed.username).lower(),
        host=parsed.hostname.lower(),
        port=parsed.port,
        params=params,
        name=name,
        source=source,
    )


def parse_source(text: str, source: str) -> list[VlessNode]:
    nodes: list[VlessNode] = []
    for uri in extract_vless(text):
        node = parse_vless(uri, source)
        if node is not None:
            nodes.append(node)
    return nodes


def is_secure(node: VlessNode) -> bool:
    return node.params.get("security", "none").lower() in {"tls", "reality"}
