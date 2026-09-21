from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from parser import VlessNode


TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
IP_RE = re.compile(r"^ip=([^\r\n]+)$", re.MULTILINE)
FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android"}


@dataclass
class RealCheckResult:
    nodes: list[VlessNode]
    selected: int
    unsupported: int
    invalid_batches: int


def _truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}


def _transport(node: VlessNode) -> dict[str, object] | None:
    params = node.params
    transport_type = params.get("type", "tcp").lower()
    path = params.get("path", "")
    host = params.get("host", "")

    if transport_type == "tcp":
        if params.get("headertype", "none").lower() != "http":
            return None
        return {
            "type": "http",
            "host": [host] if host else [],
            "path": path,
        }
    if transport_type == "ws":
        headers = {"Host": host} if host else {}
        return {"type": "ws", "path": path or "/", "headers": headers}
    if transport_type == "grpc":
        return {"type": "grpc", "service_name": params.get("servicename", "")}
    if transport_type == "http":
        return {"type": "http", "host": [host] if host else [], "path": path}
    if transport_type == "httpupgrade":
        return {"type": "httpupgrade", "host": host, "path": path or "/"}
    return None


def _outbound(node: VlessNode, tag: str) -> dict[str, object] | None:
    params = node.params
    security = params.get("security", "none").lower()
    if security not in {"tls", "reality"}:
        return None

    server_name = params.get("sni") or node.host
    tls: dict[str, object] = {"enabled": True, "server_name": server_name}
    if _truthy(params.get("insecure", "")) or _truthy(params.get("allowinsecure", "")):
        tls["insecure"] = True

    fingerprint = params.get("fp", "").lower()
    if fingerprint == "random":
        fingerprint = "chrome"
    if security == "reality" and not fingerprint:
        fingerprint = "chrome"
    if fingerprint in FINGERPRINTS:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    if security == "reality":
        public_key = params.get("pbk", params.get("publickey", ""))
        short_id = params.get("sid", "")
        if not public_key or (short_id and not re.fullmatch(r"[0-9a-fA-F]{1,16}", short_id)):
            return None
        reality: dict[str, object] = {"enabled": True, "public_key": public_key}
        if short_id:
            reality["short_id"] = short_id
        tls["reality"] = reality

    outbound: dict[str, object] = {
        "type": "vless",
        "tag": tag,
        "server": node.host,
        "server_port": node.port,
        "uuid": node.uuid,
        "tls": tls,
    }
    if params.get("flow"):
        outbound["flow"] = params["flow"]
    transport = _transport(node)
    if transport is not None:
        outbound["transport"] = transport
    elif params.get("type", "tcp").lower() not in {"tcp", ""}:
        return None
    return outbound


def _batch_config(nodes: list[VlessNode], start_port: int) -> tuple[dict[str, object], list[tuple[VlessNode, int]], int]:
    inbounds: list[dict[str, object]] = []
    outbounds: list[dict[str, object]] = [{"type": "direct", "tag": "direct"}]
    rules: list[dict[str, object]] = []
    supported: list[tuple[VlessNode, int]] = []
    unsupported = 0

    for index, node in enumerate(nodes):
        outbound_tag = f"node-{index}"
        outbound = _outbound(node, outbound_tag)
        if outbound is None:
            unsupported += 1
            continue
        inbound_tag = f"in-{index}"
        port = start_port + index
        inbounds.append(
            {
                "type": "socks",
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )
        outbounds.append(outbound)
        rules.append({"inbound": [inbound_tag], "outbound": outbound_tag})
        supported.append((node, port))

    return (
        {
            "log": {"level": "error"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules, "final": "direct"},
        },
        supported,
        unsupported,
    )


def _curl_trace(port: int, timeout: float) -> tuple[float, str] | None:
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if not curl:
        raise RuntimeError("curl is required for the sing-box traffic check")

    started = time.perf_counter()
    completed = subprocess.run(
        [
            curl,
            "--fail",
            "--silent",
            "--show-error",
            "--socks5-hostname",
            f"127.0.0.1:{port}",
            "--connect-timeout",
            str(min(timeout, 4)),
            "--max-time",
            str(timeout),
            TRACE_URL,
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 2,
    )
    if completed.returncode != 0:
        return None
    match = IP_RE.search(completed.stdout)
    if not match:
        return None
    return round((time.perf_counter() - started) * 1000, 1), match.group(1).strip()


def _check_batch(
    nodes: list[VlessNode],
    sing_box: str,
    start_port: int,
    timeout: float,
) -> tuple[list[VlessNode], int, bool]:
    config, supported, unsupported = _batch_config(nodes, start_port)
    if not supported:
        return [], unsupported, False

    with tempfile.TemporaryDirectory(prefix="vless-singbox-") as directory:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        try:
            checked = subprocess.run(
                [sing_box, "check", "-c", str(config_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return [], unsupported, True
        if checked.returncode != 0:
            return [], unsupported, True

        try:
            process = subprocess.Popen(
                [sing_box, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return [], unsupported, True
        try:
            time.sleep(0.25)
            if process.poll() is not None:
                return [], unsupported, True
            working: list[VlessNode] = []
            with ThreadPoolExecutor(max_workers=len(supported)) as executor:
                futures = {
                    executor.submit(_curl_trace, port, timeout): node
                    for node, port in supported
                }
                for future in as_completed(futures):
                    node = futures[future]
                    try:
                        result = future.result()
                    except (OSError, subprocess.SubprocessError, RuntimeError):
                        result = None
                    if result is None:
                        continue
                    node.latency_ms, node.exit_ip = result
                    working.append(node)
            return working, unsupported, False
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def check_nodes_via_singbox(
    nodes: list[VlessNode],
    sing_box: str,
    limit: int = 2000,
    timeout: float = 8.0,
    batch_size: int = 64,
    base_port: int = 20000,
) -> RealCheckResult:
    if limit < 1 or batch_size < 1:
        raise ValueError("limit and batch_size must be positive")
    if not shutil.which(sing_box) and not Path(sing_box).is_file():
        raise FileNotFoundError(f"sing-box binary not found: {sing_box}")

    selected_nodes = nodes[:limit]
    working: list[VlessNode] = []
    unsupported = 0
    invalid_batches = 0
    for offset in range(0, len(selected_nodes), batch_size):
        batch = selected_nodes[offset : offset + batch_size]
        batch_working, batch_unsupported, invalid = _check_batch(
            batch,
            sing_box,
            base_port,
            timeout,
        )
        working.extend(batch_working)
        unsupported += batch_unsupported
        invalid_batches += int(invalid)
        print(
            f"VLESS check: {min(offset + len(batch), len(selected_nodes))}/{len(selected_nodes)}, "
            f"working={len(working)}",
            flush=True,
        )
    return RealCheckResult(
        nodes=sorted(working, key=lambda node: (node.latency_ms or float("inf"), node.host, node.port)),
        selected=len(selected_nodes),
        unsupported=unsupported,
        invalid_batches=invalid_batches,
    )
