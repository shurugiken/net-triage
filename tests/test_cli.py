"""Tests for the CLI layer and report rendering. Network seams are mocked."""

import json

import pytest

from net_triage import checks
from net_triage.checks import CheckResult, FAIL, PASS, WARN
from net_triage.cli import _parse_ports, main
from net_triage.report import render_json, render_text

from .conftest import make_addrinfo


# --- port parsing ------------------------------------------------------------


def test_parse_ports_basic():
    assert _parse_ports("80,443,22") == (80, 443, 22)


def test_parse_ports_dedupes_and_strips():
    assert _parse_ports(" 80 , 80, 443 ") == (80, 443)


def test_parse_ports_rejects_non_numeric():
    with pytest.raises(ValueError):
        _parse_ports("80,abc")


def test_parse_ports_rejects_out_of_range():
    with pytest.raises(ValueError):
        _parse_ports("0")
    with pytest.raises(ValueError):
        _parse_ports("70000")


def test_parse_ports_rejects_empty():
    with pytest.raises(ValueError):
        _parse_ports(",, ,")


# --- report rendering --------------------------------------------------------


def _sample_results():
    return [
        CheckResult("dns", PASS, "DNS OK", {"addresses": ["1.2.3.4"]}),
        CheckResult("tcp:443", WARN, "slow connect"),
        CheckResult("http", FAIL, "500 error", {"status": 500}),
    ]


def test_render_text_contains_markers_and_overall():
    text = render_text("example.com", _sample_results())
    assert "net-triage report for: example.com" in text
    assert "[ OK ]" in text
    assert "[WARN]" in text
    assert "[FAIL]" in text
    assert "OVERALL: FAIL" in text


def test_render_json_is_valid_and_structured():
    out = render_json("example.com", _sample_results())
    parsed = json.loads(out)
    assert parsed["host"] == "example.com"
    assert parsed["overall"] == FAIL
    assert len(parsed["checks"]) == 3
    assert parsed["checks"][0]["name"] == "dns"


# --- main() end-to-end (mocked network) --------------------------------------


def _patch_all_pass(monkeypatch):
    from .conftest import FakeSocket

    monkeypatch.setattr(checks, "_getaddrinfo", lambda host: make_addrinfo())
    monkeypatch.setattr(checks, "_open_connection", lambda h, p, t: FakeSocket())
    monkeypatch.setattr(checks, "_http_request", lambda h, p, tls, t: (200, "OK"))


def test_main_text_output(monkeypatch, capsys):
    _patch_all_pass(monkeypatch)
    code = main(["example.com", "--ports", "443"])
    out = capsys.readouterr().out
    assert "net-triage report for: example.com" in out
    assert "OVERALL:" in out
    assert code in (0, 1)  # PASS or WARN depending on measured latency


def test_main_json_output(monkeypatch, capsys):
    _patch_all_pass(monkeypatch)
    code = main(["example.com", "--ports", "443", "--json"])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["host"] == "example.com"
    assert "checks" in parsed
    assert code in (0, 1)


def test_main_dns_failure_exit_code(monkeypatch, capsys):
    import socket as _socket

    def boom(host):
        raise _socket.gaierror("nope")

    monkeypatch.setattr(checks, "_getaddrinfo", boom)
    code = main(["nope.invalid"])
    out = capsys.readouterr().out
    assert "OVERALL: FAIL" in out
    assert code == 2  # FAIL -> exit 2


def test_main_invalid_ports_exit_code(capsys):
    code = main(["example.com", "--ports", "abc"])
    err = capsys.readouterr().err
    assert "error" in err
    assert code == 3


def test_main_invalid_timeout_exit_code(capsys):
    code = main(["example.com", "--timeout", "0"])
    err = capsys.readouterr().err
    assert "timeout must be positive" in err
    assert code == 3


def test_main_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "net-triage" in out
