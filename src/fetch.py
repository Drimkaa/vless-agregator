from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_SOURCE_BYTES = 25 * 1024 * 1024


@dataclass
class FetchResult:
    name: str
    url: str
    text: str = ""
    error: str | None = None


def fetch_source(source: dict[str, Any], timeout: float = 30) -> FetchResult:
    name = str(source["name"])
    url = str(source["url"])
    request = Request(
        url,
        headers={
            "User-Agent": "vless-agregator/0.1",
            "Accept": "text/plain,*/*;q=0.8",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_SOURCE_BYTES + 1)
        if len(body) > MAX_SOURCE_BYTES:
            raise ValueError(f"response is larger than {MAX_SOURCE_BYTES} bytes")
        return FetchResult(name=name, url=url, text=body.decode("utf-8", errors="replace"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return FetchResult(name=name, url=url, error=f"{type(exc).__name__}: {exc}")


def fetch_all(sources: list[dict[str, Any]], max_workers: int = 12) -> list[FetchResult]:
    enabled = [source for source in sources if source.get("enabled", True)]
    results: list[FetchResult | None] = [None] * len(enabled)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(fetch_source, source): index
            for index, source in enumerate(enabled)
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()

    return [result for result in results if result is not None]
