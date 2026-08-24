#!/usr/bin/env python3
"""Lightweight proxy-router management UI server.

Default mode is read-only. Set PROXY_MANAGER_ALLOW_WRITE=1 to enable applying
mihomo assignment changes after backup and validation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import difflib
import json
import os
import re
import shutil
import socket
import ssl
import threading
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import ProxyHandler, build_opener, Request
from urllib.error import URLError, HTTPError

import yaml

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
MIHOMO_CONFIG = Path(os.environ.get("MIHOMO_CONFIG", "/etc/mihomo/config.yaml"))
DNSMASQ_CONFIG = Path(os.environ.get("DNSMASQ_CONFIG", "/etc/dnsmasq.conf"))
LEASES_FILE = Path(os.environ.get("DNSMASQ_LEASES", "/var/lib/misc/dnsmasq.leases"))
INVENTORY_FILE = Path(os.environ.get("PROXMOX_INVENTORY", str(ROOT / "data" / "proxmox-inventory.json")))
HEALTH_FILE = Path(os.environ.get("PROXY_HEALTH_FILE", str(ROOT / "data" / "proxy-health.json")))
PROXY_HISTORY_FILE = Path(os.environ.get("PROXY_HISTORY_FILE", str(ROOT / "data" / "proxy-history.json")))
ALLOW_WRITE = os.environ.get("PROXY_MANAGER_ALLOW_WRITE") == "1"
HEALTH_TTL_SECONDS = int(os.environ.get("PROXY_HEALTH_TTL_SECONDS", "3600"))
HEALTH_TEST_URL = os.environ.get("PROXY_HEALTH_TEST_URL", "https://www.gstatic.com/generate_204")
QUALITY_TEST_URL = os.environ.get("PROXY_QUALITY_TEST_URL", "https://speed.cloudflare.com/__down?bytes=65536")
QUALITY_CONCURRENCY = int(os.environ.get("PROXY_QUALITY_CONCURRENCY", "30"))
QUALITY_TIMEOUT_SECONDS = int(os.environ.get("PROXY_QUALITY_TIMEOUT_SECONDS", "8"))
HEALTH_LOCK = threading.Lock()

PROXMOX_HOSTS = [
    {"name": "pve1", "address": os.environ.get("PVE1_ADDR", "192.0.2.1"), "managementBridge": "vmbr0", "proxyBridge": "vmbr1", "proxySubnet": "172.16.101.0/24"},
    {"name": "pve2", "address": os.environ.get("PVE2_ADDR", "192.0.2.2"), "managementBridge": "vmbr0", "proxyBridge": "vmbr1", "proxySubnet": "172.16.100.0/24"},
    {"name": "pve3", "address": os.environ.get("PVE3_ADDR", "192.0.2.3"), "managementBridge": "vmbr0", "proxyBridge": "vmbr2", "proxySubnet": "172.16.101.0/24"},
    {"name": "pve4", "address": os.environ.get("PVE4_ADDR", "192.0.2.4"), "managementBridge": "vmbr0", "proxyBridge": "vmbr1", "proxySubnet": "172.16.101.0/24"},
]

PVE1_HOST = os.environ.get("PVE1_HOST", "192.0.2.1")
PVE1_SSH_LOCAL_USER = os.environ.get("PVE1_SSH_LOCAL_USER", "proxy-router")
PVE1_PROXY_BRIDGE = "vmbr1"
PVE1_VM_MIN = 101
PVE1_VM_MAX = 140
PVE1_IP_BASE = "172.16.101"
PVE1_IP_OFFSET = 79

VM_HINTS = {
    "172.16.100": "pve2",
    "172.16.101": "pve3/pve4",
}

ASSIGNMENT_RE = re.compile(r"^\s*-\s*SRC-IP-CIDR,(172\.16\.(?:100|101)\.\d+)/32,([^\s,#]+)")
DHCP_RE = re.compile(r"dhcp-host=([^,]+),(172\.16\.(?:100|101)\.\d+)\s*(?:#\s*(.*))?")
DOMAIN_BYPASS_RE = re.compile(r"^\s*-\s+(DOMAIN(?:-SUFFIX)?),([^,\s#]+),([^\s,#]+)")
IP_CIDR_RULE_RE = re.compile(r"^\s*-\s+(IP-CIDR),([^,\s#]+),([^\s,#]+)")
AND_DOMAIN_BYPASS_RE = re.compile(r"^\s*-\s+AND,\(\(SRC-IP-CIDR,([0-9.]+)/32\),\((DOMAIN(?:-SUFFIX)?),([^)]+)\)\),([^\s,#]+)")  # noqa: E501
AND_IP_CIDR_RULE_RE = re.compile(r"^\s*-\s+AND,\(\(SRC-IP-CIDR,([0-9.]+)/32\),\((IP-CIDR),([^)]+)\)\),([^\s,#]+)")  # noqa: E501
_MANAGED_TARGETS = {"DIRECT", "direct-enp1s0", "direct-enp4s0", "REJECT", "REJECT-DROP"}
PROXY_USE_RE = re.compile(r"using (proxy-[0-9]+|direct-enp[0-9]s[0-9])")
VM_USE_RE = re.compile(r"\[TCP\]\s+(172\.16\.(?:100|101)\.\d+):\d+\s+-->.*?using\s+(proxy-[0-9]+|direct-enp[0-9]s[0-9])")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(command: list[str], timeout: int = 5) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:  # pragma: no cover - defensive operational helper
        return 1, "", str(exc)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text()
    except FileNotFoundError:
        return ""


def load_yaml_config() -> dict[str, Any]:
    text = read_text(MIHOMO_CONFIG)
    if not text:
        return {}
    return yaml.safe_load(text) or {}


def load_health() -> dict[str, Any]:
    if not HEALTH_FILE.exists():
        return {}
    try:
        data = json.loads(read_text(HEALTH_FILE))
    except json.JSONDecodeError:
        return {}
    return data.get("proxies", {}) if isinstance(data, dict) else {}


def save_health(health: dict[str, Any]) -> None:
    HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"updatedAt": utc_now(), "testUrl": HEALTH_TEST_URL, "proxies": health}
    HEALTH_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def health_is_stale(health: dict[str, Any]) -> bool:
    if not health:
        return True
    checked_values = [row.get("checkedAtEpoch", 0) for row in health.values() if isinstance(row, dict)]
    if not checked_values:
        return True
    return time.time() - min(checked_values) > HEALTH_TTL_SECONDS


def proxy_definitions(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    definitions = {}
    for item in config.get("proxies", []) or []:
        name = item.get("name")
        if name:
            definitions[name] = item
    return definitions


def probe_proxy(proxy: dict[str, Any]) -> dict[str, Any]:
    name = proxy.get("name", "unknown")
    proxy_type = proxy.get("type", "unknown")
    started = time.perf_counter()
    checked_epoch = time.time()
    base = {
        "name": name,
        "type": proxy_type,
        "checkedAt": utc_now(),
        "checkedAtEpoch": checked_epoch,
        "testUrl": QUALITY_TEST_URL,
        "concurrency": QUALITY_CONCURRENCY,
    }
    try:
        if proxy_type in {"http", "socks5", "direct"}:
            return {**base, **probe_quality(proxy, started)}
        return {**base, "status": "unknown", "latencyMs": None, "message": f"unsupported type {proxy_type}", "successCount": 0, "failureCount": QUALITY_CONCURRENCY, "downloadMbps": 0}
    except Exception as exc:  # pragma: no cover - operational safety net
        return {**base, "status": "down", "latencyMs": round((time.perf_counter() - started) * 1000), "message": str(exc), "successCount": 0, "failureCount": QUALITY_CONCURRENCY, "downloadMbps": 0}


def probe_quality(proxy: dict[str, Any], started: float) -> dict[str, Any]:
    worker = quality_worker_for(proxy)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=QUALITY_CONCURRENCY) as executor:
        futures = [executor.submit(worker) for _ in range(QUALITY_CONCURRENCY)]
        for future in concurrent.futures.as_completed(futures, timeout=QUALITY_TIMEOUT_SECONDS + 3):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"ok": False, "bytes": 0, "duration": QUALITY_TIMEOUT_SECONDS, "error": str(exc)})
    while len(results) < QUALITY_CONCURRENCY:
        results.append({"ok": False, "bytes": 0, "duration": QUALITY_TIMEOUT_SECONDS, "error": "timeout"})
    successes = [row for row in results if row.get("ok")]
    failures = [row for row in results if not row.get("ok")]
    total_bytes = sum(int(row.get("bytes", 0)) for row in successes)
    wall_seconds = max(0.001, time.perf_counter() - started)
    avg_latency = round(sum(float(row.get("duration", 0)) for row in successes) * 1000 / len(successes)) if successes else None
    download_mbps = round(total_bytes * 8 / wall_seconds / 1_000_000, 2)
    success_rate = round(len(successes) / QUALITY_CONCURRENCY * 100, 1)
    if len(successes) == 0:
        status = "down"
    elif len(successes) < QUALITY_CONCURRENCY * 0.8:
        status = "degraded"
    elif download_mbps < 1:
        status = "degraded"
    else:
        status = "healthy"
    first_error = failures[0].get("error") if failures else ""
    message = f"{len(successes)}/{QUALITY_CONCURRENCY} ok, {download_mbps} Mbps"
    if first_error:
        message = f"{message}; first error: {first_error}"
    return {
        "status": status,
        "latencyMs": avg_latency,
        "downloadMbps": download_mbps,
        "totalBytes": total_bytes,
        "successCount": len(successes),
        "failureCount": len(failures),
        "successRate": success_rate,
        "durationMs": round(wall_seconds * 1000),
        "message": message,
    }


def quality_worker_for(proxy: dict[str, Any]):
    proxy_type = proxy.get("type")
    if proxy_type == "http":
        return lambda: download_via_http_proxy(proxy)
    if proxy_type == "socks5":
        return lambda: download_via_socks5(proxy)
    if proxy_type == "direct":
        return lambda: download_direct(proxy)
    return lambda: {"ok": False, "bytes": 0, "duration": 0, "error": f"unsupported type {proxy_type}"}


def timed_result(func):
    started = time.perf_counter()
    try:
        bytes_read = func()
        return {"ok": True, "bytes": bytes_read, "duration": time.perf_counter() - started}
    except Exception as exc:
        return {"ok": False, "bytes": 0, "duration": time.perf_counter() - started, "error": str(exc)}


def download_via_http_proxy(proxy: dict[str, Any]) -> dict[str, Any]:
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return {"ok": False, "bytes": 0, "duration": 0, "error": "missing server or port"}
    auth = ""
    username = proxy.get("username")
    password = proxy.get("password")
    if username and password:
        auth = f"{username}:{password}@"
    proxy_url = f"http://{auth}{server}:{port}"
    def run_download() -> int:
        opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
        request = Request(QUALITY_TEST_URL, headers={"User-Agent": "proxy-router-manager/1.0"})
        with opener.open(request, timeout=QUALITY_TIMEOUT_SECONDS) as response:
            return len(response.read())
    return timed_result(run_download)


def download_via_socks5(proxy: dict[str, Any]) -> dict[str, Any]:
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return {"ok": False, "bytes": 0, "duration": 0, "error": "missing server or port"}
    parsed = urlparse(QUALITY_TEST_URL)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"ok": False, "bytes": 0, "duration": 0, "error": "SOCKS5 worker requires HTTPS URL"}
    def run_download() -> int:
        raw = socket.create_connection((str(server), int(port)), timeout=QUALITY_TIMEOUT_SECONDS)
        try:
            raw.settimeout(QUALITY_TIMEOUT_SECONDS)
            socks5_connect(raw, parsed.hostname, parsed.port or 443, proxy.get("username"), proxy.get("password"))
            context = ssl.create_default_context()
            with context.wrap_socket(raw, server_hostname=parsed.hostname) as tls:
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                request = f"GET {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\nUser-Agent: proxy-router-manager/1.0\r\nConnection: close\r\n\r\n"
                tls.sendall(request.encode("ascii"))
                data = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                return len(data.split(b"\r\n\r\n", 1)[-1]) if b"\r\n\r\n" in data else len(data)
        finally:
            try:
                raw.close()
            except OSError:
                pass
    return timed_result(run_download)


def socks5_connect(sock: socket.socket, host: str, port: int, username: str | None, password: str | None) -> None:
    methods = [0x00]
    if username and password:
        methods.append(0x02)
    sock.sendall(bytes([0x05, len(methods), *methods]))
    response = sock.recv(2)
    if len(response) != 2 or response[0] != 0x05:
        raise OSError("invalid SOCKS5 greeting")
    if response[1] == 0x02:
        user = str(username).encode()
        pwd = str(password).encode()
        sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd)
        auth_response = sock.recv(2)
        if len(auth_response) != 2 or auth_response[1] != 0x00:
            raise OSError("SOCKS5 authentication failed")
    elif response[1] != 0x00:
        raise OSError("SOCKS5 server rejected supported auth methods")
    host_bytes = host.encode("idna")
    request = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + int(port).to_bytes(2, "big")
    sock.sendall(request)
    reply = sock.recv(4)
    if len(reply) != 4 or reply[1] != 0x00:
        raise OSError(f"SOCKS5 connect failed: {reply.hex() if reply else 'empty reply'}")
    address_type = reply[3]
    if address_type == 0x01:
        sock.recv(4)
    elif address_type == 0x03:
        length = sock.recv(1)[0]
        sock.recv(length)
    elif address_type == 0x04:
        sock.recv(16)
    sock.recv(2)


def download_direct(proxy: dict[str, Any]) -> dict[str, Any]:
    interface_name = proxy.get("interface-name")
    command = ["curl", "-fsS", "--max-time", "8"]
    if interface_name:
        command.extend(["--interface", str(interface_name)])
    command.append(QUALITY_TEST_URL)
    def run_download() -> int:
        code, stdout, stderr = run(command, timeout=QUALITY_TIMEOUT_SECONDS + 2)
        if code != 0:
            raise OSError(stderr or stdout or f"curl exit {code}")
        return len(stdout.encode())
    return timed_result(run_download)


def probe_many(names: list[str] | None = None) -> dict[str, Any]:
    config = load_yaml_config()
    definitions = proxy_definitions(config)
    selected = names or sorted(definitions, key=proxy_sort_key)
    results = {}
    jobs = []
    for name in selected:
        proxy = definitions.get(name)
        if not proxy:
            results[name] = {"name": name, "status": "unknown", "checkedAt": utc_now(), "checkedAtEpoch": time.time(), "message": "proxy not found"}
            continue
        jobs.append((name, proxy))
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, max(1, len(jobs)))) as executor:
        future_to_name = {executor.submit(probe_proxy, proxy): name for name, proxy in jobs}
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"name": name, "status": "down", "checkedAt": utc_now(), "checkedAtEpoch": time.time(), "message": str(exc)}
    with HEALTH_LOCK:
        health = load_health()
        health.update(results)
        save_health(health)
    return {"checkedAt": utc_now(), "count": len(results), "results": results}


def health_scheduler() -> None:
    while True:
        try:
            if health_is_stale(load_health()):
                probe_many()
        except Exception as exc:
            sys.stderr.write(f"proxy health scheduler error: {exc}\n")
        time.sleep(HEALTH_TTL_SECONDS)


def parse_proxies(config: dict[str, Any], assignments_by_proxy: dict[str, list[dict[str, Any]]], usage: Counter[str], health: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    health = health or {}
    proxies = []
    for item in config.get("proxies", []) or []:
        name = item.get("name")
        if not name:
            continue
        proxy_type = item.get("type", "unknown")
        server = item.get("server") or item.get("interface-name") or ""
        port = item.get("port")
        provider = "Direct" if proxy_type == "direct" else "Oxylabs" if "oxylabs" in str(server).lower() else "Static"
        proxies.append({
            "name": name,
            "type": proxy_type,
            "provider": provider,
            "server": f"{server}:{port}" if port else str(server),
            "enabled": True,
            "assignedVmCount": len(assignments_by_proxy.get(name, [])),
            "usageHits1h": usage.get(name, 0),
            "status": health.get(name, {}).get("status", "unknown"),
            "health": health.get(name, {"status": "unknown"}),
        })
    for direct_name in ("direct-enp1s0", "direct-enp4s0"):
        if not any(proxy["name"] == direct_name for proxy in proxies):
            proxies.append({
                "name": direct_name,
                "type": "direct",
                "provider": "Direct",
                "server": direct_name.replace("direct-", ""),
                "enabled": True,
                "assignedVmCount": len(assignments_by_proxy.get(direct_name, [])),
                "usageHits1h": usage.get(direct_name, 0),
                "status": health.get(direct_name, {}).get("status", "unknown"),
                "health": health.get(direct_name, {"status": "unknown"}),
            })
    return sorted(proxies, key=lambda row: proxy_sort_key(row["name"]))


def proxy_sort_key(name: str) -> tuple[int, int, str]:
    match = re.match(r"proxy-(\d+)$", name)
    if match:
        return (0, int(match.group(1)), name)
    if name.startswith("direct-"):
        return (2, 0, name)
    return (1, 0, name)


def parse_dhcp() -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    previous_comment = ""
    for line in read_text(DNSMASQ_CONFIG).splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            previous_comment = stripped.lstrip("# ")
            continue
        match = DHCP_RE.search(line)
        if not match:
            if stripped:
                previous_comment = ""
            continue
        mac, ip, note = match.groups()
        rows[ip] = {"ip": ip, "mac": mac.upper(), "note": note or previous_comment}
        previous_comment = ""
    return rows


def parse_leases() -> dict[str, dict[str, Any]]:
    leases: dict[str, dict[str, Any]] = {}
    for line in read_text(LEASES_FILE).splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        expires, mac, ip, hostname = parts[:4]
        if ip.startswith(("172.16.100.", "172.16.101.")):
            leases[ip] = {"ip": ip, "mac": mac.upper(), "hostname": hostname, "expires": expires}
    return leases


def parse_assignments() -> list[dict[str, Any]]:
    assignments = []
    previous_comments: list[str] = []
    for line_number, line in enumerate(read_text(MIHOMO_CONFIG).splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            previous_comments.append(stripped.lstrip("# "))
            previous_comments = previous_comments[-3:]
            continue
        match = ASSIGNMENT_RE.match(line)
        if not match:
            continue
        ip, proxy = match.groups()
        assignments.append({
            "ip": ip,
            "proxy": proxy,
            "line": line_number,
            "comment": next((comment for comment in reversed(previous_comments) if re.search(r"\bVM\s*\d{2,4}\b", comment, re.I)), ""),
            "source": "mihomo",
        })
        previous_comments = []
    return assignments


def parse_domain_bypass_rules() -> list[dict[str, Any]]:
    rules = []
    for line_number, line in enumerate(read_text(MIHOMO_CONFIG).splitlines(), start=1):
        m = DOMAIN_BYPASS_RE.match(line)
        if m:
            rule_type, domain, target = m.groups()
            if target in _MANAGED_TARGETS:
                rules.append({
                    "ruleType": rule_type, "domain": domain, "target": target,
                    "vmIp": None, "line": line_number, "managed": "domain-bypass" in line,
                })
            continue
        m = IP_CIDR_RULE_RE.match(line)
        if m:
            rule_type, cidr, target = m.groups()
            # Only show user-managed IP-CIDR rules; local-network DIRECT rules have no marker
            if target in _MANAGED_TARGETS and "domain-bypass" in line:
                rules.append({
                    "ruleType": rule_type, "domain": cidr, "target": target,
                    "vmIp": None, "line": line_number, "managed": True,
                })
            continue
        m = AND_DOMAIN_BYPASS_RE.match(line)
        if m:
            vm_ip, rule_type, domain, target = m.groups()
            if target in _MANAGED_TARGETS:
                rules.append({
                    "ruleType": f"AND-{rule_type}", "domain": domain, "target": target,
                    "vmIp": vm_ip, "line": line_number, "managed": "domain-bypass" in line,
                })
            continue
        m = AND_IP_CIDR_RULE_RE.match(line)
        if m:
            vm_ip, rule_type, cidr, target = m.groups()
            if target in _MANAGED_TARGETS and "domain-bypass" in line:
                rules.append({
                    "ruleType": f"AND-{rule_type}", "domain": cidr, "target": target,
                    "vmIp": vm_ip, "line": line_number, "managed": True,
                })
    return rules


def add_domain_bypass_rule(domain: str, rule_type: str, target: str, vm_ip: str | None) -> dict[str, Any]:
    if not ALLOW_WRITE:
        return {"ok": False, "errors": ["Server is read-only. Set PROXY_MANAGER_ALLOW_WRITE=1."]}
    if rule_type not in {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR"}:
        return {"ok": False, "errors": [f"Invalid rule type: {rule_type}"]}
    if target not in _MANAGED_TARGETS:
        return {"ok": False, "errors": [f"Invalid target: {target}. Must be one of {sorted(_MANAGED_TARGETS)}"]}
    if vm_ip and not re.match(r"^172\.16\.(100|101)\.\d{1,3}$", vm_ip):
        return {"ok": False, "errors": [f"Invalid VM IP: {vm_ip}"]}
    if rule_type == "IP-CIDR":
        if not re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", domain):
            return {"ok": False, "errors": [f"Invalid IP/CIDR format: {domain}"]}
    else:
        if not re.match(r"^[a-zA-Z0-9.\-]+$", domain):
            return {"ok": False, "errors": [f"Invalid domain: {domain}"]}
    for rule in parse_domain_bypass_rules():
        if rule["domain"] == domain and rule["target"] == target and rule["vmIp"] == vm_ip:
            return {"ok": False, "errors": ["An identical rule already exists."]}
    if rule_type == "IP-CIDR":
        if vm_ip:
            new_line = f"  - AND,((SRC-IP-CIDR,{vm_ip}/32),(IP-CIDR,{domain})),{target}  # domain-bypass\n"
        else:
            new_line = f"  - IP-CIDR,{domain},{target}  # domain-bypass\n"
    elif vm_ip:
        new_line = f"  - AND,((SRC-IP-CIDR,{vm_ip}/32),({rule_type},{domain})),{target}  # domain-bypass\n"
    else:
        new_line = f"  - {rule_type},{domain},{target}  # domain-bypass\n"
    config_text = read_text(MIHOMO_CONFIG)
    lines = config_text.splitlines(True)
    # Must insert before the first SRC-IP-CIDR rule so domain rules take priority over per-VM assignments
    insert_at = next(
        (i for i, line in enumerate(lines) if re.match(r"^\s+-\s+SRC-IP-CIDR,172\.16\.", line)),
        None,
    )
    if insert_at is None:
        for i, line in enumerate(lines):
            if line.strip().startswith("- MATCH,"):
                insert_at = i
                break
    if insert_at is None:
        return {"ok": False, "errors": ["Could not find insertion point in mihomo config."]}
    lines.insert(insert_at, new_line)
    new_text = "".join(lines)
    backup = MIHOMO_CONFIG.with_name(f"{MIHOMO_CONFIG.name}.bak-domain-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(MIHOMO_CONFIG, backup)
    MIHOMO_CONFIG.write_text(new_text, encoding="utf-8")
    config = load_yaml_config()
    if not config.get("rules"):
        shutil.copy2(backup, MIHOMO_CONFIG)
        return {"ok": False, "errors": ["Config validation failed; backup restored."]}
    code, stdout, stderr = run(["systemctl", "restart", "mihomo"], timeout=15)
    if code != 0:
        shutil.copy2(backup, MIHOMO_CONFIG)
        run(["systemctl", "restart", "mihomo"], timeout=15)
        return {"ok": False, "errors": [f"mihomo restart failed; backup restored: {stderr or stdout}"]}
    return {"ok": True, "backup": str(backup), "message": f"Rule added: {new_line.strip()}"}


def remove_domain_bypass_rule(line_number: int) -> dict[str, Any]:
    if not ALLOW_WRITE:
        return {"ok": False, "errors": ["Server is read-only."]}
    config_text = read_text(MIHOMO_CONFIG)
    lines = config_text.splitlines(True)
    if line_number < 1 or line_number > len(lines):
        return {"ok": False, "errors": [f"Invalid line number: {line_number}"]}
    line = lines[line_number - 1]
    stripped = line.strip()
    if not (re.match(r"^-\s+DOMAIN(?:-SUFFIX)?,", stripped)
            or re.match(r"^-\s+IP-CIDR,", stripped)
            or re.match(r"^-\s+AND,\(\(SRC-IP-CIDR,", stripped)):
        return {"ok": False, "errors": ["Line is not a managed bypass/block rule."]}
    backup = MIHOMO_CONFIG.with_name(f"{MIHOMO_CONFIG.name}.bak-domain-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(MIHOMO_CONFIG, backup)
    del lines[line_number - 1]
    MIHOMO_CONFIG.write_text("".join(lines), encoding="utf-8")
    config = load_yaml_config()
    if not config.get("rules"):
        shutil.copy2(backup, MIHOMO_CONFIG)
        return {"ok": False, "errors": ["Config validation failed; backup restored."]}
    code, stdout, stderr = run(["systemctl", "restart", "mihomo"], timeout=15)
    if code != 0:
        shutil.copy2(backup, MIHOMO_CONFIG)
        run(["systemctl", "restart", "mihomo"], timeout=15)
        return {"ok": False, "errors": [f"mihomo restart failed; backup restored: {stderr or stdout}"]}
    return {"ok": True, "backup": str(backup), "removedLine": stripped, "message": "Rule removed and mihomo restarted."}


def infer_host(ip: str, note: str = "") -> str:
    lower = note.lower()
    for host in ("pve1", "pve2", "pve3", "pve4"):
        if host in lower:
            return host
    if ip.startswith("172.16.100."):
        return "pve2"
    return "pve3/pve4"


def infer_vm_id(note: str, comment: str) -> str:
    text = f"{note} {comment}"
    match = re.search(r"\bVM\s*(\d{2,4})\b", text, re.I)
    return match.group(1) if match else ""


def vm_label(host: str, vm_id: str, fallback: str) -> str:
    if host and vm_id:
        return f"{host}:vm{vm_id}"
    return fallback


def load_inventory() -> list[dict[str, Any]]:
    if not INVENTORY_FILE.exists():
        return []
    try:
        data = json.loads(read_text(INVENTORY_FILE))
    except json.JSONDecodeError:
        return []
    return data.get("vms", []) if isinstance(data, dict) else []


def build_vms(assignments: list[dict[str, Any]], dhcp: dict[str, dict[str, Any]], leases: dict[str, dict[str, Any]], inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip = {row["ip"]: dict(row) for row in assignments}
    for ip, row in dhcp.items():
        by_ip.setdefault(ip, {"ip": ip, "proxy": None, "line": None, "comment": "", "source": "dnsmasq"})
    for ip, row in leases.items():
        by_ip.setdefault(ip, {"ip": ip, "proxy": None, "line": None, "comment": "", "source": "lease"})

    vms = []
    for ip in sorted(by_ip, key=ip_key):
        item = by_ip[ip]
        static = dhcp.get(ip, {})
        lease = leases.get(ip, {})
        note = static.get("note", "")
        comment = item.get("comment", "")
        vm_id = infer_vm_id(note, comment)
        has_dhcp = ip in dhcp
        has_assignment = bool(item.get("proxy"))
        has_lease = ip in leases
        host = infer_host(ip, note + " " + comment)
        label = vm_label(host, vm_id, ip)
        if has_assignment and has_dhcp:
            state = "managed"
        elif has_assignment or has_dhcp or has_lease:
            state = "partial"
        else:
            state = "unmanaged"
        vms.append({
            "id": label,
            "label": label,
            "vmId": vm_id,
            "name": lease.get("hostname") or note or comment or ip,
            "ip": ip,
            "mac": static.get("mac") or lease.get("mac") or "",
            "host": host,
            "proxy": item.get("proxy"),
            "status": state,
            "hasDhcp": has_dhcp,
            "hasLease": has_lease,
            "hasAssignment": has_assignment,
            "note": note,
            "comment": comment,
            "line": item.get("line"),
            "bridge": "",
            "proxmoxStatus": "",
        })
    by_host_vm: dict[tuple[str, str], dict[str, Any]] = {}
    for vm in vms:
        if vm.get("host") and vm.get("vmId"):
            by_host_vm[(str(vm["host"]), str(vm["vmId"]))] = vm
    for item in inventory:
        host = item.get("host", "")
        vm_id = str(item.get("vmId", ""))
        if not host or not vm_id:
            continue
        existing = by_host_vm.get((host, vm_id))
        if existing:
            existing["name"] = item.get("name") or existing.get("name") or f"VM{vm_id}"
            existing["bridge"] = item.get("bridge", "")
            existing["proxmoxStatus"] = item.get("status", "")
            continue
        label = vm_label(host, vm_id, f"VM{vm_id}")
        vms.append({
            "id": label,
            "label": label,
            "vmId": vm_id,
            "name": item.get("name") or f"VM{vm_id}",
            "ip": "",
            "mac": item.get("mac", ""),
            "host": host,
            "proxy": None,
            "status": "unmanaged",
            "hasDhcp": False,
            "hasLease": False,
            "hasAssignment": False,
            "note": "未接入 proxy / 初始状态",
            "comment": "",
            "line": None,
            "bridge": item.get("bridge", ""),
            "proxmoxStatus": item.get("status", ""),
        })
    return sorted(vms, key=vm_sort_key)


def ip_key(ip: str) -> tuple[int, int, int, int]:
    return tuple(int(part) for part in ip.split("."))  # type: ignore[return-value]


def vm_sort_key(vm: dict[str, Any]) -> tuple[str, int, tuple[int, int, int, int], str]:
    vm_id = int(vm["vmId"]) if str(vm.get("vmId", "")).isdigit() else 99999
    ip = vm.get("ip") or "255.255.255.255"
    return (vm.get("host") or "", vm_id, ip_key(ip), vm.get("name") or "")


def get_usage() -> Counter[str]:
    code, stdout, _stderr = run(["journalctl", "-u", "mihomo", "--since", "1 hour ago", "--no-pager"], timeout=8)
    if code != 0:
        return Counter()
    return Counter(PROXY_USE_RE.findall(stdout))


def get_vm_usage() -> dict[str, dict[str, Any]]:
    code, stdout, _stderr = run(["journalctl", "-u", "mihomo", "--since", "1 hour ago", "--no-pager"], timeout=8)
    if code != 0:
        return {}
    usage: dict[str, dict[str, Any]] = {}
    for ip, proxy in VM_USE_RE.findall(stdout):
        row = usage.setdefault(ip, {"hits1h": 0, "lastProxy": "", "byProxy": {}})
        row["hits1h"] += 1
        row["lastProxy"] = proxy
        row["byProxy"][proxy] = row["byProxy"].get(proxy, 0) + 1
    return usage


def service_status(name: str) -> str:
    code, stdout, _stderr = run(["systemctl", "is-active", name], timeout=3)
    return stdout if code == 0 and stdout else "unknown"


def router_snapshot() -> dict[str, Any]:
    _code, addresses, _err = run(["ip", "-br", "addr"], timeout=3)
    _code, routes, _err = run(["ip", "route"], timeout=3)
    hostname = socket.gethostname()
    return {
        "hostname": hostname,
        "interfaces": addresses.splitlines() if addresses else [],
        "routes": routes.splitlines() if routes else [],
        "services": {
            "mihomo": service_status("mihomo"),
            "dnsmasq": service_status("dnsmasq"),
            "nginx": service_status("nginx"),
        },
    }


def state_snapshot() -> dict[str, Any]:
    config = load_yaml_config()
    dhcp = parse_dhcp()
    leases = parse_leases()
    assignments = parse_assignments()
    inventory = load_inventory()
    usage = get_usage()
    vm_usage = get_vm_usage()
    health = load_health()
    archived = archived_proxy_names()
    history = load_proxy_history()
    domain_bypass_rules = parse_domain_bypass_rules()
    vms = build_vms(assignments, dhcp, leases, inventory)
    for vm in vms:
        row = vm_usage.get(vm.get("ip") or "", {})
        vm["usageHits1h"] = row.get("hits1h", 0)
        vm["lastProxyUsed"] = row.get("lastProxy", "")
        vm["assignedProxyHits1h"] = row.get("byProxy", {}).get(vm.get("proxy") or "", 0)
    by_proxy: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for vm in vms:
        if vm.get("proxy"):
            by_proxy[vm["proxy"]].append(vm)
    proxies = parse_proxies(config, by_proxy, usage, health)
    for proxy in proxies:
        proxy["archived"] = proxy["name"] in archived
        if proxy["archived"]:
            proxy["enabled"] = False
    warnings = build_warnings(vms, proxies)
    return {
        "generatedAt": utc_now(),
        "readOnly": not ALLOW_WRITE,
        "configPaths": {"mihomo": str(MIHOMO_CONFIG), "dnsmasq": str(DNSMASQ_CONFIG), "leases": str(LEASES_FILE)},
        "router": router_snapshot(),
        "proxmoxHosts": PROXMOX_HOSTS,
        "proxies": proxies,
        "vms": vms,
        "proxyHistory": history,
        "summary": {
            "proxyCount": len(proxies),
            "managedVmCount": sum(1 for vm in vms if vm["status"] == "managed"),
            "partialVmCount": sum(1 for vm in vms if vm["status"] == "partial"),
            "unmanagedVmCount": sum(1 for vm in vms if vm["status"] == "unmanaged"),
            "leaseCount": len(leases),
            "assignmentCount": len(assignments),
            "activeProxyCount": sum(1 for proxy in proxies if proxy["enabled"]),
            "archivedProxyCount": sum(1 for proxy in proxies if proxy.get("archived")),
            "healthyProxyCount": sum(1 for proxy in proxies if proxy.get("health", {}).get("status") == "healthy"),
        },
        "warnings": warnings,
        "domainBypassRules": domain_bypass_rules,
    }


def build_warnings(vms: list[dict[str, Any]], proxies: list[dict[str, Any]]) -> list[dict[str, str]]:
    proxy_names = {proxy["name"] for proxy in proxies}
    warnings = []
    seen_ips = Counter(vm["ip"] for vm in vms)
    for ip, count in seen_ips.items():
        if count > 1:
            warnings.append({"level": "critical", "message": f"Duplicate VM IP detected: {ip}"})
    for vm in vms:
        if vm.get("proxy") and vm["proxy"] not in proxy_names:
            warnings.append({"level": "critical", "message": f"{vm['ip']} points to missing proxy {vm['proxy']}"})
        if vm["status"] == "partial":
            warnings.append({"level": "warning", "message": f"{vm['ip']} has incomplete DHCP/assignment/lease state"})
    return warnings[:80]


def make_plan(changes: list[dict[str, str]]) -> dict[str, Any]:
    current = {row["ip"]: row for row in parse_assignments()}
    config_text = read_text(MIHOMO_CONFIG)
    new_text = config_text
    normalized = []
    errors = []
    archived = archived_proxy_names()
    proxy_names = {proxy["name"] for proxy in parse_proxies(load_yaml_config(), defaultdict(list), Counter(), load_health()) if proxy["name"] not in archived}
    for change in changes:
        ip = change.get("ip", "").strip()
        new_proxy = change.get("toProxy", "").strip()
        old_proxy = change.get("fromProxy") or current.get(ip, {}).get("proxy")
        if not re.match(r"^172\.16\.(100|101)\.\d+$", ip):
            errors.append(f"Invalid VM IP: {ip}")
            continue
        if new_proxy not in proxy_names:
            errors.append(f"Unknown target proxy for {ip}: {new_proxy}")
            continue
        if ip not in current:
            errors.append(f"No existing mihomo SRC-IP-CIDR rule for {ip}; first version only edits existing assignments")
            continue
        old_proxy = current[ip]["proxy"]
        if old_proxy == new_proxy:
            continue
        pattern = re.compile(rf"(^\s*-\s*SRC-IP-CIDR,{re.escape(ip)}/32,){re.escape(str(old_proxy))}(\s*(?:#.*)?$)", re.M)
        if not pattern.search(new_text):
            errors.append(f"Could not locate current rule for {ip} -> {old_proxy}")
            continue
        new_text = pattern.sub(rf"\g<1>{new_proxy}\2", new_text, count=1)
        normalized.append({"ip": ip, "fromProxy": old_proxy, "toProxy": new_proxy})
    diff = "\n".join(difflib.unified_diff(config_text.splitlines(), new_text.splitlines(), fromfile=str(MIHOMO_CONFIG), tofile=f"{MIHOMO_CONFIG} (planned)", lineterm=""))
    return {"ok": not errors, "readOnly": not ALLOW_WRITE, "changes": normalized, "errors": errors, "diff": diff}


def build_text_with_assignment_changes(config_text: str, changes: list[dict[str, str]]) -> tuple[str, list[str], list[dict[str, str]]]:
    current = {row["ip"]: row for row in parse_assignments()}
    new_text = config_text
    normalized = []
    errors = []
    for change in changes:
        ip = change.get("ip", "").strip()
        new_proxy = change.get("toProxy", "").strip()
        if ip not in current:
            errors.append(f"No existing mihomo SRC-IP-CIDR rule for {ip}")
            continue
        old_proxy = current[ip]["proxy"]
        if old_proxy == new_proxy:
            continue
        pattern = re.compile(rf"(^\s*-\s*SRC-IP-CIDR,{re.escape(ip)}/32,){re.escape(str(old_proxy))}(\s*(?:#.*)?$)", re.M)
        if not pattern.search(new_text):
            errors.append(f"Could not locate current rule for {ip} -> {old_proxy}")
            continue
        new_text = pattern.sub(rf"\g<1>{new_proxy}\2", new_text, count=1)
        normalized.append({"ip": ip, "fromProxy": str(old_proxy), "toProxy": new_proxy})
    return new_text, errors, normalized


def recommend_reassignments(proxy_name: str) -> list[dict[str, str]]:
    assignments = parse_assignments()
    affected = [row for row in assignments if row["proxy"] == proxy_name]
    if not affected:
        return []
    config = load_yaml_config()
    usage = get_usage()
    health = load_health()
    archived = archived_proxy_names()
    counts = Counter(row["proxy"] for row in assignments)
    candidates = []
    for name, definition in proxy_definitions(config).items():
        if name == proxy_name or name in archived or definition.get("type") == "direct":
            continue
        health_row = health.get(name, {})
        if health_row.get("status") != "healthy":
            continue
        candidates.append(name)
    candidates.sort(key=lambda name: (counts[name], usage[name], proxy_sort_key(name)))
    if not candidates:
        return []
    changes = []
    for row in affected:
        target = candidates[0]
        counts[target] += 1
        candidates.sort(key=lambda name: (counts[name], usage[name], proxy_sort_key(name)))
        changes.append({"ip": row["ip"], "fromProxy": proxy_name, "toProxy": target})
    return changes


def remove_proxy_from_text(config_text: str, proxy_name: str) -> str:
    lines = config_text.splitlines()
    result = []
    in_proxy_block = False
    for line in lines:
        if re.match(rf"^\s*-\s*name:\s*['\"]?{re.escape(proxy_name)}['\"]?\s*$", line):
            in_proxy_block = True
            continue
        if in_proxy_block and re.match(r"^\s*-\s*name:\s*", line):
            in_proxy_block = False
        if in_proxy_block:
            continue
        if re.match(rf"^\s*-\s*{re.escape(proxy_name)}\s*$", line):
            continue
        result.append(line)
    return "\n".join(result) + "\n"


def proxy_delete_plan(proxy_name: str) -> dict[str, Any]:
    config = load_yaml_config()
    definitions = proxy_definitions(config)
    errors = []
    if proxy_name not in definitions:
        errors.append(f"Proxy not found: {proxy_name}")
    if definitions.get(proxy_name, {}).get("type") == "direct":
        errors.append("Direct routes cannot be deleted from this UI")
    health = load_health().get(proxy_name, {})
    if health.get("status") not in {"down", "degraded"}:
        errors.append(f"Proxy {proxy_name} is not marked down/degraded; run health check first or avoid deleting healthy proxies")
    changes = recommend_reassignments(proxy_name)
    return {
        "ok": not errors,
        "mode": "presentation-archive",
        "proxy": proxy_name,
        "health": health,
        "reassignments": changes,
        "affectedVmCount": len(changes),
        "errors": errors,
        "diff": "",
        "message": f"{proxy_name} will be archived in the UI only. Production mihomo config will not be modified.",
    }


def append_proxy_history(entry: dict[str, Any]) -> None:
    PROXY_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if PROXY_HISTORY_FILE.exists():
        try:
            data = json.loads(read_text(PROXY_HISTORY_FILE))
            history = data.get("history", []) if isinstance(data, dict) else []
        except json.JSONDecodeError:
            history = []
    history.append(entry)
    PROXY_HISTORY_FILE.write_text(json.dumps({"updatedAt": utc_now(), "history": history}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_proxy_history() -> list[dict[str, Any]]:
    if not PROXY_HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(read_text(PROXY_HISTORY_FILE))
    except json.JSONDecodeError:
        return []
    return data.get("history", []) if isinstance(data, dict) else []


def archived_proxy_names() -> set[str]:
    archived: set[str] = set()
    for entry in load_proxy_history():
        proxy = entry.get("proxy")
        if not proxy:
            continue
        if entry.get("action") == "archive":
            archived.add(proxy)
        elif entry.get("action") == "restore":
            archived.discard(proxy)
    return archived


def apply_proxy_delete(proxy_name: str) -> dict[str, Any]:
    plan = proxy_delete_plan(proxy_name)
    if not plan["ok"]:
        return plan
    append_proxy_history({"action": "archive", "proxy": proxy_name, "archivedAt": utc_now(), "health": plan["health"], "affectedVmCount": plan["affectedVmCount"], "reassignments": plan["reassignments"]})
    return {**plan, "ok": True, "message": f"Archived {proxy_name} in UI only. Production config was not modified."}


def apply_plan(changes: list[dict[str, str]]) -> dict[str, Any]:
    plan = make_plan(changes)
    if not plan["ok"]:
        return plan
    if not plan["changes"]:
        return {**plan, "ok": True, "message": "No effective assignment changes to apply."}
    if not ALLOW_WRITE:
        return {**plan, "ok": False, "errors": ["Server is read-only. Set PROXY_MANAGER_ALLOW_WRITE=1 to enable applying changes."]}
    original = read_text(MIHOMO_CONFIG)
    new_lines = original.splitlines()
    current = {row["ip"]: row for row in parse_assignments()}
    for change in plan["changes"]:
        ip = change["ip"]
        old_proxy = current[ip]["proxy"]
        new_proxy = change["toProxy"]
        line_index = int(current[ip]["line"]) - 1
        new_lines[line_index] = re.sub(rf"(SRC-IP-CIDR,{re.escape(ip)}/32,){re.escape(old_proxy)}", rf"\g<1>{new_proxy}", new_lines[line_index], count=1)
    backup = MIHOMO_CONFIG.with_name(f"{MIHOMO_CONFIG.name}.bak-proxy-manager-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(MIHOMO_CONFIG, backup)
    MIHOMO_CONFIG.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    config = load_yaml_config()
    if not config.get("rules"):
        shutil.copy2(backup, MIHOMO_CONFIG)
        return {**plan, "ok": False, "errors": ["Validation failed after write; restored backup."]}
    code, stdout, stderr = run(["systemctl", "restart", "mihomo"], timeout=15)
    if code != 0:
        shutil.copy2(backup, MIHOMO_CONFIG)
        run(["systemctl", "restart", "mihomo"], timeout=15)
        return {**plan, "ok": False, "backup": str(backup), "errors": [f"mihomo restart failed and backup was restored: {stderr or stdout}"]}
    return {**plan, "ok": True, "backup": str(backup), "message": "Applied and restarted mihomo."}


def pve1_ip_for_vm(vm_id: int) -> str:
    return f"{PVE1_IP_BASE}.{vm_id + PVE1_IP_OFFSET}"


def ssh_pve1(command: str, timeout: int = 12) -> tuple[int, str, str]:
    ssh_command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new", f"root@{PVE1_HOST}", command]
    if os.geteuid() == 0 and PVE1_SSH_LOCAL_USER:
        ssh_command = ["sudo", "-n", "-H", "-u", PVE1_SSH_LOCAL_USER, *ssh_command]
    return run(ssh_command, timeout=timeout)


def parse_net0(config_text: str) -> tuple[str, str] | None:
    for line in config_text.splitlines():
        if not line.startswith("net0:"):
            continue
        value = line.split(":", 1)[1].strip()
        match = re.match(r"([^=]+)=([^,]+)(.*)", value)
        if not match:
            return None
        model, mac, rest = match.groups()
        rest = re.sub(r",?bridge=[^,]+", "", rest)
        return mac.upper(), f"{model}={mac}{rest},bridge={PVE1_PROXY_BRIDGE}"
    return None


def update_dnsmasq_host(vm_id: int, mac: str, ip: str) -> str:
    backup = DNSMASQ_CONFIG.with_name(f"{DNSMASQ_CONFIG.name}.bak-pve1-vm{vm_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(DNSMASQ_CONFIG, backup)
    mac_lower = mac.lower()
    entry = f"dhcp-host={mac},{ip}  # VM {vm_id} pve1\n"
    lines = []
    replaced = False
    for line in read_text(DNSMASQ_CONFIG).splitlines(True):
        lower = line.lower()
        if line.lstrip().startswith("dhcp-host=") and (mac_lower in lower or ip in line):
            if not replaced:
                lines.append(entry)
                replaced = True
            continue
        lines.append(line)
    if not replaced:
        lines.append("\n# pve1 VM101-140 static DHCP on 172.16.101.180-219\n")
        lines.append(entry)
    DNSMASQ_CONFIG.write_text("".join(lines), encoding="utf-8")
    return str(backup)


def update_mihomo_assignment(vm_id: int, ip: str, proxy_name: str) -> str:
    backup = MIHOMO_CONFIG.with_name(f"{MIHOMO_CONFIG.name}.bak-pve1-vm{vm_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(MIHOMO_CONFIG, backup)
    text = read_text(MIHOMO_CONFIG)
    rule_re = re.compile(rf"(^\s*-\s*SRC-IP-CIDR,{re.escape(ip)}/32,)([^\s,#]+)(\s*(?:#.*)?$)", re.M)
    if rule_re.search(text):
        text = rule_re.sub(rf"\g<1>{proxy_name}\3", text, count=1)
    else:
        entry = f"  # VM {vm_id} pve1 -> {proxy_name}\n  - SRC-IP-CIDR,{ip}/32,{proxy_name}\n"
        marker = "  - MATCH,vm-lb\n"
        if marker not in text:
            raise RuntimeError("Could not locate final MATCH rule in mihomo config")
        text = text.replace(marker, entry + marker, 1)
    MIHOMO_CONFIG.write_text(text, encoding="utf-8")
    config = load_yaml_config()
    if not config.get("rules"):
        shutil.copy2(backup, MIHOMO_CONFIG)
        raise RuntimeError("mihomo validation failed; restored backup")
    return str(backup)


def update_inventory_for_pve1(vm_id: int, name: str, bridge: str, status: str) -> None:
    data = {"generatedFrom": "manual snapshot", "vms": []}
    if INVENTORY_FILE.exists():
        try:
            data = json.loads(read_text(INVENTORY_FILE))
        except json.JSONDecodeError:
            data = {"generatedFrom": "manual snapshot", "vms": []}
    rows = data.setdefault("vms", [])
    target = None
    for row in rows:
        if row.get("host") == "pve1" and str(row.get("vmId")) == str(vm_id):
            target = row
            break
    if target is None:
        target = {"host": "pve1", "vmId": str(vm_id)}
        rows.append(target)
    target.update({"name": name or f"VM{vm_id}", "status": status, "bridge": bridge})
    INVENTORY_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def apply_pve1_vm_proxy(vm_id: int, proxy_name: str) -> dict[str, Any]:
    if not ALLOW_WRITE:
        return {"ok": False, "errors": ["Server is read-only. Set PROXY_MANAGER_ALLOW_WRITE=1 to enable applying changes."]}
    if vm_id < PVE1_VM_MIN or vm_id > PVE1_VM_MAX:
        return {"ok": False, "errors": [f"VM {vm_id} is outside pve1 range {PVE1_VM_MIN}-{PVE1_VM_MAX}"]}
    config = load_yaml_config()
    definitions = proxy_definitions(config)
    if proxy_name not in definitions or proxy_name in archived_proxy_names():
        return {"ok": False, "errors": [f"Unknown or archived proxy: {proxy_name}"]}
    if definitions[proxy_name].get("type") == "direct":
        return {"ok": False, "errors": ["Select a real proxy, not a direct route"]}
    ip = pve1_ip_for_vm(vm_id)
    errors = []
    steps: list[str] = []
    code, vm_config, stderr = ssh_pve1(f"qm config {vm_id}")
    if code != 0:
        return {"ok": False, "errors": [stderr or f"Could not read pve1 VM {vm_id} config"]}
    name_match = re.search(r"^name:\s*(.+)$", vm_config, re.M)
    name = name_match.group(1).strip() if name_match else f"VM{vm_id}"
    net0 = parse_net0(vm_config)
    if not net0:
        return {"ok": False, "errors": [f"Could not parse VM {vm_id} net0"]}
    mac, net_value = net0
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    code, _stdout, stderr = ssh_pve1(f"cp -a /etc/pve/qemu-server/{vm_id}.conf /etc/pve/qemu-server/{vm_id}.conf.bak-proxy-manager-{timestamp} && qm set {vm_id} -net0 {net_value}", timeout=20)
    if code != 0:
        return {"ok": False, "errors": [stderr or f"Could not switch VM {vm_id} to {PVE1_PROXY_BRIDGE}"]}
    steps.append(f"pve1 VM{vm_id} net0 switched to {PVE1_PROXY_BRIDGE}")
    try:
        dnsmasq_backup = update_dnsmasq_host(vm_id, mac, ip)
        steps.append(f"dnsmasq static lease {ip} added")
        mihomo_backup = update_mihomo_assignment(vm_id, ip, proxy_name)
        steps.append(f"mihomo rule {ip} -> {proxy_name} added")
    except Exception as exc:
        errors.append(str(exc))
        return {"ok": False, "vmId": vm_id, "ip": ip, "proxy": proxy_name, "steps": steps, "errors": errors}
    for service in ("dnsmasq", "mihomo"):
        code, stdout, stderr = run(["systemctl", "restart", service], timeout=15)
        if code != 0:
            return {"ok": False, "vmId": vm_id, "ip": ip, "proxy": proxy_name, "steps": steps, "errors": [f"{service} restart failed: {stderr or stdout}"]}
        steps.append(f"{service} restarted")
    code, status_stdout, _stderr = ssh_pve1(f"qm status {vm_id}")
    status = "running" if "status: running" in status_stdout else "unknown"
    update_inventory_for_pve1(vm_id, name, PVE1_PROXY_BRIDGE, status)
    lease_text = read_text(LEASES_FILE).lower()
    lease_ok = ip in lease_text and mac.lower() in lease_text
    neighbor_code, neighbor_stdout, _neighbor_stderr = run(["ip", "neigh", "show", ip], timeout=3)
    neighbor_ok = neighbor_code == 0 and mac.lower() in neighbor_stdout.lower()
    usage = get_vm_usage().get(ip, {})
    assigned_proxy_hits = usage.get("byProxy", {}).get(proxy_name, 0)
    proxy_hit_ok = assigned_proxy_hits > 0
    tests = {"bridge": True, "lease": lease_ok, "neighbor": neighbor_ok, "proxyTraffic": proxy_hit_ok, "usageHits1h": usage.get("hits1h", 0), "assignedProxyHits1h": assigned_proxy_hits, "lastProxyUsed": usage.get("lastProxy", "")}
    return {
        "ok": lease_ok and neighbor_ok,
        "configured": True,
        "verified": proxy_hit_ok,
        "vmId": vm_id,
        "name": name,
        "ip": ip,
        "mac": mac,
        "proxy": proxy_name,
        "bridge": PVE1_PROXY_BRIDGE,
        "tests": tests,
        "steps": steps,
        "backups": {"dnsmasq": dnsmasq_backup, "mihomo": mihomo_backup, "pve": f"/etc/pve/qemu-server/{vm_id}.conf.bak-proxy-manager-{timestamp}"},
        "message": "Configured. Waiting for VM traffic through mihomo to mark proxy test verified." if not proxy_hit_ok else "Configured and proxy traffic verified.",
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (datetime.now().strftime("%H:%M:%S"), fmt % args))

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/state":
            self.send_json(state_snapshot())
            return
        if path == "/healthz":
            self.send_json({"ok": True, "time": utc_now()})
            return
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        payload = self.read_json()
        if path == "/api/plan":
            self.send_json(make_plan(payload.get("changes", [])))
            return
        if path == "/api/apply":
            self.send_json(apply_plan(payload.get("changes", [])), status=HTTPStatus.BAD_REQUEST if not ALLOW_WRITE else HTTPStatus.OK)
            return
        if path == "/api/health/check":
            name = payload.get("proxy")
            names = [name] if name else None
            self.send_json(probe_many(names))
            return
        if path == "/api/proxies/delete-plan":
            self.send_json(proxy_delete_plan(str(payload.get("proxy", ""))))
            return
        if path == "/api/proxies/delete":
            self.send_json(apply_proxy_delete(str(payload.get("proxy", ""))))
            return
        if path == "/api/pve1/configure-vm":
            try:
                vm_id = int(payload.get("vmId"))
            except (TypeError, ValueError):
                self.send_json({"ok": False, "errors": ["Invalid vmId"]}, status=HTTPStatus.BAD_REQUEST)
                return
            self.send_json(apply_pve1_vm_proxy(vm_id, str(payload.get("proxy", ""))))
            return
        if path == "/api/domain-bypass/add":
            domain = str(payload.get("domain", "")).strip().lower()
            rule_type = str(payload.get("ruleType", "DOMAIN-SUFFIX")).strip()
            target = str(payload.get("target", "DIRECT")).strip()
            vm_ip_raw = payload.get("vmIp")
            vm_ip = str(vm_ip_raw).strip() if vm_ip_raw else None
            self.send_json(add_domain_bypass_rule(domain, rule_type, target, vm_ip))
            return
        if path == "/api/domain-bypass/remove":
            try:
                line_number = int(payload.get("line"))
            except (TypeError, ValueError):
                self.send_json({"ok": False, "errors": ["Invalid line number"]}, status=HTTPStatus.BAD_REQUEST)
                return
            self.send_json(remove_domain_bypass_rule(line_number))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy Router management UI")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8088")))
    args = parser.parse_args()
    threading.Thread(target=health_scheduler, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Proxy Manager UI listening on http://{args.host}:{args.port}")
    print(f"Mode: {'write-enabled' if ALLOW_WRITE else 'read-only preview'}")
    server.serve_forever()


if __name__ == "__main__":
    main()
