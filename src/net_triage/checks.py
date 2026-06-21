"""Network checks for net-triage.

Each check returns a :class:`CheckResult`. Checks are deliberately written so
that the only network-touching calls (``socket.getaddrinfo``, ``socket.create_connection``,
and an HTTP request via ``http.client``) live in small functions that tests can
mock or monkeypatch. No raw ICMP/ping is used, so the tool runs without root.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

# Verdict constants.
PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

DEFAULT_PORTS = (80, 443, 22, 3389)

# Latency thresholds (milliseconds) used to grade connect/HTTP latency.
LATENCY_WARN_MS = 200.0
LATENCY_FAIL_MS = 1000.0


@dataclass
class CheckResult:
    """Result of a single check.

    ``name`` is a short identifier (e.g. "dns", "tcp:443", "http").
    ``verdict`` is one of PASS/WARN/FAIL.
    ``summary`` is a one-line human-readable string.
    ``detail`` holds structured data for the JSON output.
    """

    name: str
    verdict: str
    summary: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "summary": self.summary,
            "detail": self.detail,
        }


def _grade_latency(latency_ms: float) -> str:
    """Grade a latency measurement into PASS/WARN/FAIL."""
    if latency_ms >= LATENCY_FAIL_MS:
        return FAIL
    if latency_ms >= LATENCY_WARN_MS:
        return WARN
    return PASS


# --- Network seams (mock these in tests) -------------------------------------


def _getaddrinfo(host: str):
    """Thin wrapper over socket.getaddrinfo for both A and AAAA records."""
    return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)


def _open_connection(host: str, port: int, timeout: float):
    """Open a TCP connection and return the socket. Caller closes it."""
    return socket.create_connection((host, port), timeout=timeout)


# --- Checks ------------------------------------------------------------------


def check_dns(host: str) -> CheckResult:
    """Resolve ``host`` to A/AAAA addresses and measure resolution time."""
    start = time.perf_counter()
    try:
        infos = _getaddrinfo(host)
    except socket.gaierror as exc:
        return CheckResult(
            name="dns",
            verdict=FAIL,
            summary=f"DNS resolution failed for {host}: {exc}",
            detail={"host": host, "error": str(exc), "addresses": []},
        )
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    ipv4, ipv6 = [], []
    for info in infos:
        family = info[0]
        addr = info[4][0]
        if family == socket.AF_INET and addr not in ipv4:
            ipv4.append(addr)
        elif family == socket.AF_INET6 and addr not in ipv6:
            ipv6.append(addr)

    addresses = ipv4 + ipv6
    if not addresses:
        return CheckResult(
            name="dns",
            verdict=FAIL,
            summary=f"DNS returned no addresses for {host}",
            detail={"host": host, "addresses": [], "resolve_ms": round(elapsed_ms, 2)},
        )

    verdict = _grade_latency(elapsed_ms)
    summary = (
        f"DNS OK for {host}: {len(ipv4)} A, {len(ipv6)} AAAA "
        f"in {elapsed_ms:.1f} ms"
    )
    return CheckResult(
        name="dns",
        verdict=verdict,
        summary=summary,
        detail={
            "host": host,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "addresses": addresses,
            "resolve_ms": round(elapsed_ms, 2),
        },
    )


def check_tcp_port(host: str, port: int, timeout: float = 5.0) -> CheckResult:
    """Attempt a TCP connection to ``host:port`` and measure connect latency."""
    start = time.perf_counter()
    try:
        sock = _open_connection(host, port, timeout)
    except (socket.timeout, TimeoutError) as exc:
        return CheckResult(
            name=f"tcp:{port}",
            verdict=FAIL,
            summary=f"TCP {host}:{port} timed out after {timeout:.0f}s",
            detail={"host": host, "port": port, "reachable": False, "error": str(exc) or "timeout"},
        )
    except OSError as exc:
        return CheckResult(
            name=f"tcp:{port}",
            verdict=FAIL,
            summary=f"TCP {host}:{port} refused/unreachable: {exc}",
            detail={"host": host, "port": port, "reachable": False, "error": str(exc)},
        )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    try:
        sock.close()
    except OSError:
        pass

    verdict = _grade_latency(elapsed_ms)
    summary = f"TCP {host}:{port} reachable in {elapsed_ms:.1f} ms"
    return CheckResult(
        name=f"tcp:{port}",
        verdict=verdict,
        summary=summary,
        detail={
            "host": host,
            "port": port,
            "reachable": True,
            "connect_ms": round(elapsed_ms, 2),
        },
    )


def _http_request(host: str, port: int, use_tls: bool, timeout: float):
    """Issue a single HEAD request and return (status, reason).

    Isolated so tests can monkeypatch it without standing up a server.
    """
    if use_tls:
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        return resp.status, resp.reason
    finally:
        conn.close()


def check_http(host: str, port: int, use_tls: bool, timeout: float = 5.0) -> CheckResult:
    """Perform an HTTP(S) HEAD request and grade by status code + latency."""
    scheme = "https" if use_tls else "http"
    start = time.perf_counter()
    try:
        status, reason = _http_request(host, port, use_tls, timeout)
    except (socket.timeout, TimeoutError) as exc:
        return CheckResult(
            name="http",
            verdict=FAIL,
            summary=f"{scheme}://{host}:{port} timed out: {exc or 'timeout'}",
            detail={"host": host, "port": port, "scheme": scheme, "error": str(exc) or "timeout"},
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return CheckResult(
            name="http",
            verdict=FAIL,
            summary=f"{scheme}://{host}:{port} request failed: {exc}",
            detail={"host": host, "port": port, "scheme": scheme, "error": str(exc)},
        )
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    # Grade: 2xx/3xx PASS, 4xx WARN (server reachable but rejected), 5xx FAIL.
    if 200 <= status < 400:
        verdict = PASS
    elif 400 <= status < 500:
        verdict = WARN
    else:
        verdict = FAIL
    # A slow-but-OK response is downgraded to WARN.
    if verdict == PASS and elapsed_ms >= LATENCY_WARN_MS:
        verdict = WARN

    summary = f"{scheme}://{host}:{port} -> {status} {reason} in {elapsed_ms:.1f} ms"
    return CheckResult(
        name="http",
        verdict=verdict,
        summary=summary,
        detail={
            "host": host,
            "port": port,
            "scheme": scheme,
            "status": status,
            "reason": reason,
            "latency_ms": round(elapsed_ms, 2),
        },
    )


def estimate_latency(host: str, port: int, timeout: float = 5.0, samples: int = 3) -> CheckResult:
    """Estimate round-trip latency via repeated TCP connects (no ICMP).

    Connecting to an open port and timing the handshake gives a usable RTT
    proxy without raw sockets, so it works as an unprivileged user.
    """
    times: list[float] = []
    last_error: Optional[str] = None
    for _ in range(max(1, samples)):
        start = time.perf_counter()
        try:
            sock = _open_connection(host, port, timeout)
        except OSError as exc:
            last_error = str(exc) or exc.__class__.__name__
            continue
        times.append((time.perf_counter() - start) * 1000.0)
        try:
            sock.close()
        except OSError:
            pass

    if not times:
        return CheckResult(
            name="latency",
            verdict=FAIL,
            summary=f"Latency estimate failed for {host}:{port}: {last_error}",
            detail={"host": host, "port": port, "samples": 0, "error": last_error},
        )

    avg = sum(times) / len(times)
    verdict = _grade_latency(avg)
    summary = (
        f"Latency ~{avg:.1f} ms avg over {len(times)} connect(s) "
        f"(min {min(times):.1f}, max {max(times):.1f}) to {host}:{port}"
    )
    return CheckResult(
        name="latency",
        verdict=verdict,
        summary=summary,
        detail={
            "host": host,
            "port": port,
            "samples": len(times),
            "avg_ms": round(avg, 2),
            "min_ms": round(min(times), 2),
            "max_ms": round(max(times), 2),
        },
    )


def triage(
    host: str,
    ports: Optional[tuple[int, ...]] = None,
    timeout: float = 5.0,
    latency_samples: int = 3,
) -> list[CheckResult]:
    """Run the full triage suite for ``host`` and return all check results."""
    if ports is None:
        ports = DEFAULT_PORTS

    results: list[CheckResult] = []

    dns = check_dns(host)
    results.append(dns)

    # If DNS failed there is no point probing TCP/HTTP; report and stop early.
    if dns.verdict == FAIL:
        return results

    open_ports: list[int] = []
    for port in ports:
        tcp = check_tcp_port(host, port, timeout=timeout)
        results.append(tcp)
        if tcp.detail.get("reachable"):
            open_ports.append(port)

    # HTTP(S) checks only when the relevant web port is open.
    if 443 in open_ports:
        results.append(check_http(host, 443, use_tls=True, timeout=timeout))
    if 80 in open_ports:
        results.append(check_http(host, 80, use_tls=False, timeout=timeout))

    # Latency estimate against the first reachable port (fall back to first port).
    latency_port = open_ports[0] if open_ports else ports[0]
    results.append(
        estimate_latency(host, latency_port, timeout=timeout, samples=latency_samples)
    )

    return results


def overall_verdict(results: list[CheckResult]) -> str:
    """Roll up individual verdicts into a single overall verdict."""
    verdicts = {r.verdict for r in results}
    if FAIL in verdicts:
        return FAIL
    if WARN in verdicts:
        return WARN
    return PASS
