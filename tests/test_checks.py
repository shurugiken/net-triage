"""Tests for individual checks. All network seams are mocked."""

import socket

import pytest

from net_triage import checks
from net_triage.checks import (
    FAIL,
    PASS,
    WARN,
    check_dns,
    check_http,
    check_tcp_port,
    estimate_latency,
    overall_verdict,
    triage,
)

from .conftest import make_addrinfo


# --- DNS ---------------------------------------------------------------------


def test_check_dns_success(monkeypatch):
    monkeypatch.setattr(checks, "_getaddrinfo", lambda host: make_addrinfo())
    result = check_dns("example.com")
    assert result.verdict == PASS
    assert result.detail["ipv4"] == ["93.184.216.34"]
    assert result.detail["ipv6"]
    assert "addresses" in result.detail


def test_check_dns_dedupes_addresses(monkeypatch):
    dup = make_addrinfo(ipv4=("1.2.3.4", "1.2.3.4"), ipv6=())
    monkeypatch.setattr(checks, "_getaddrinfo", lambda host: dup)
    result = check_dns("example.com")
    assert result.detail["ipv4"] == ["1.2.3.4"]


def test_check_dns_failure(monkeypatch):
    def boom(host):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(checks, "_getaddrinfo", boom)
    result = check_dns("nope.invalid")
    assert result.verdict == FAIL
    assert result.detail["addresses"] == []


def test_check_dns_empty_result(monkeypatch):
    monkeypatch.setattr(checks, "_getaddrinfo", lambda host: [])
    result = check_dns("empty.example")
    assert result.verdict == FAIL


# --- TCP ---------------------------------------------------------------------


def test_check_tcp_port_open(monkeypatch, fake_socket):
    monkeypatch.setattr(checks, "_open_connection", lambda h, p, t: fake_socket)
    result = check_tcp_port("example.com", 443)
    assert result.verdict in (PASS, WARN)  # latency-graded; fast under test
    assert result.detail["reachable"] is True
    assert result.detail["port"] == 443
    assert fake_socket.closed is True


def test_check_tcp_port_refused(monkeypatch):
    def refused(h, p, t):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(checks, "_open_connection", refused)
    result = check_tcp_port("example.com", 22)
    assert result.verdict == FAIL
    assert result.detail["reachable"] is False


def test_check_tcp_port_timeout(monkeypatch):
    def timeout(h, p, t):
        raise socket.timeout("timed out")

    monkeypatch.setattr(checks, "_open_connection", timeout)
    result = check_tcp_port("example.com", 3389, timeout=1.0)
    assert result.verdict == FAIL
    assert result.detail["reachable"] is False


# --- HTTP --------------------------------------------------------------------


def test_check_http_200(monkeypatch):
    monkeypatch.setattr(checks, "_http_request", lambda h, p, tls, t: (200, "OK"))
    result = check_http("example.com", 443, use_tls=True)
    assert result.verdict in (PASS, WARN)
    assert result.detail["status"] == 200
    assert result.detail["scheme"] == "https"


def test_check_http_404_is_warn(monkeypatch):
    monkeypatch.setattr(checks, "_http_request", lambda h, p, tls, t: (404, "Not Found"))
    result = check_http("example.com", 80, use_tls=False)
    assert result.verdict == WARN
    assert result.detail["status"] == 404


def test_check_http_500_is_fail(monkeypatch):
    monkeypatch.setattr(checks, "_http_request", lambda h, p, tls, t: (500, "Server Error"))
    result = check_http("example.com", 443, use_tls=True)
    assert result.verdict == FAIL


def test_check_http_3xx_is_pass(monkeypatch):
    monkeypatch.setattr(checks, "_http_request", lambda h, p, tls, t: (301, "Moved"))
    result = check_http("example.com", 80, use_tls=False)
    assert result.verdict in (PASS, WARN)
    assert result.detail["status"] == 301


def test_check_http_connection_error(monkeypatch):
    def boom(h, p, tls, t):
        raise OSError("connection reset")

    monkeypatch.setattr(checks, "_http_request", boom)
    result = check_http("example.com", 443, use_tls=True)
    assert result.verdict == FAIL
    assert "error" in result.detail


# --- Latency -----------------------------------------------------------------


def test_estimate_latency_success(monkeypatch, fake_socket):
    monkeypatch.setattr(checks, "_open_connection", lambda h, p, t: fake_socket)
    result = estimate_latency("example.com", 443, samples=3)
    assert result.verdict in (PASS, WARN)
    assert result.detail["samples"] == 3
    assert "avg_ms" in result.detail


def test_estimate_latency_all_fail(monkeypatch):
    def boom(h, p, t):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(checks, "_open_connection", boom)
    result = estimate_latency("example.com", 443, samples=3)
    assert result.verdict == FAIL
    assert result.detail["samples"] == 0


def test_estimate_latency_partial(monkeypatch):
    """Some connects fail, some succeed -> still produces an estimate."""
    calls = {"n": 0}

    def flaky(h, p, t):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionRefusedError("refused")
        from .conftest import FakeSocket

        return FakeSocket()

    monkeypatch.setattr(checks, "_open_connection", flaky)
    result = estimate_latency("example.com", 443, samples=3)
    assert result.verdict in (PASS, WARN)
    assert result.detail["samples"] == 2


# --- Grading helpers ---------------------------------------------------------


def test_grade_latency_thresholds():
    assert checks._grade_latency(10.0) == PASS
    assert checks._grade_latency(checks.LATENCY_WARN_MS) == WARN
    assert checks._grade_latency(checks.LATENCY_FAIL_MS) == FAIL


def test_overall_verdict_rollup():
    from net_triage.checks import CheckResult

    ok = CheckResult("a", PASS, "ok")
    warn = CheckResult("b", WARN, "warn")
    fail = CheckResult("c", FAIL, "fail")
    assert overall_verdict([ok, ok]) == PASS
    assert overall_verdict([ok, warn]) == WARN
    assert overall_verdict([ok, warn, fail]) == FAIL


# --- triage() orchestration --------------------------------------------------


def test_triage_dns_fail_short_circuits(monkeypatch):
    def boom(host):
        raise socket.gaierror("nope")

    monkeypatch.setattr(checks, "_getaddrinfo", boom)
    results = triage("nope.invalid", ports=(443,))
    assert len(results) == 1
    assert results[0].name == "dns"
    assert results[0].verdict == FAIL


def test_triage_full_path(monkeypatch, fake_socket):
    monkeypatch.setattr(checks, "_getaddrinfo", lambda host: make_addrinfo())
    monkeypatch.setattr(checks, "_open_connection", lambda h, p, t: fake_socket)
    monkeypatch.setattr(checks, "_http_request", lambda h, p, tls, t: (200, "OK"))

    results = triage("example.com", ports=(443, 80))
    names = [r.name for r in results]
    assert names[0] == "dns"
    assert "tcp:443" in names
    assert "tcp:80" in names
    assert "http" in names  # at least one http check
    assert names[-1] == "latency"


def test_triage_skips_http_when_port_closed(monkeypatch):
    monkeypatch.setattr(checks, "_getaddrinfo", lambda host: make_addrinfo())

    def refused(h, p, t):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(checks, "_open_connection", refused)
    results = triage("example.com", ports=(443,))
    names = [r.name for r in results]
    assert "http" not in names
    # DNS pass + tcp:443 fail + latency fail
    assert "tcp:443" in names
    assert "latency" in names
