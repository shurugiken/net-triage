# net-triage

A small command-line tool for quickly triaging whether you can reach a host and
where the connection breaks down: DNS, TCP ports, HTTP(S), and round-trip
latency. It prints a clean report with a `PASS` / `WARN` / `FAIL` verdict per
check, or machine-readable JSON.

## Why this exists

When a user says "the site/app is down," the fix usually starts with a few
boring questions: does the name resolve, is the port open, does the web server
answer, and is the link slow? `net-triage` runs those checks in one command and
gives a single, skimmable answer instead of stringing together `nslookup`,
`telnet`/`Test-NetConnection`, and `curl` by hand.

It uses only the Python standard library at runtime and does **not** use raw
ICMP `ping`, so it runs as an ordinary unprivileged user. The latency estimate
is derived from timing TCP connects to an open port, which is a practical RTT
proxy without needing root or raw sockets.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/shurugiken/net-triage.git
cd net-triage
pip install -e .
```

This installs a `net-triage` console command. (For development, install the test
extra: `pip install -e ".[dev]"`.)

## Usage

```bash
# Default checks: ports 80, 443, 22, 3389
net-triage example.com

# Specific ports
net-triage example.com --ports 443,8443

# Tighter timeout, more latency samples
net-triage example.com --timeout 2 --latency-samples 5

# JSON output (for scripts / logging)
net-triage example.com --json
```

Example text report:

```
net-triage report for: example.com
============================================================
[ OK ] dns        DNS OK for example.com: 1 A, 1 AAAA in 12.4 ms
[ OK ] tcp:443    TCP example.com:443 reachable in 28.7 ms
[FAIL] tcp:22     TCP example.com:22 refused/unreachable: ...
[ OK ] http       https://example.com:443 -> 200 OK in 41.0 ms
[ OK ] latency    Latency ~27.9 ms avg over 3 connect(s) (min 26.1, max 30.2) to example.com:443
============================================================
OVERALL: FAIL
```

## Example output

Run against `github.com` with port 443 only and 5 latency samples:

```
$ net-triage github.com --ports 443 --latency-samples 5
net-triage report for: github.com
============================================================
[ OK ] dns        DNS OK for github.com: 1 A, 0 AAAA in 7.5 ms
[WARN] tcp:443    TCP github.com:443 reachable in 291.1 ms
[WARN] http       https://github.com:443 -> 200 OK in 1521.7 ms
[WARN] latency    Latency ~277.7 ms avg over 5 connect(s) (min 275.2, max 279.5) to github.com:443
============================================================
OVERALL: WARN
```

Exit code `1` — all checks reached the host, but TCP connect latency (~278 ms avg) and the
HTTP response time (~1.5 s) both crossed the WARN threshold (>200 ms).

Same host with `--json`:

```
$ net-triage github.com --ports 443 --json
{
    "host": "github.com",
    "overall": "WARN",
    "checks": [
        {
            "name": "dns",
            "verdict": "PASS",
            "summary": "DNS OK for github.com: 1 A, 0 AAAA in 7.2 ms",
            "detail": {
                "host": "github.com",
                "ipv4": ["140.82.121.3"],
                "ipv6": [],
                "addresses": ["140.82.121.3"],
                "resolve_ms": 7.16
            }
        },
        {
            "name": "tcp:443",
            "verdict": "WARN",
            "summary": "TCP github.com:443 reachable in 298.6 ms",
            "detail": {
                "host": "github.com",
                "port": 443,
                "reachable": true,
                "connect_ms": 298.62
            }
        },
        {
            "name": "http",
            "verdict": "WARN",
            "summary": "https://github.com:443 -> 200 OK in 1570.1 ms",
            "detail": {
                "host": "github.com",
                "port": 443,
                "scheme": "https",
                "status": 200,
                "reason": "OK",
                "latency_ms": 1570.08
            }
        },
        {
            "name": "latency",
            "verdict": "WARN",
            "summary": "Latency ~277.0 ms avg over 3 connect(s) (min 275.0, max 280.2) to github.com:443",
            "detail": {
                "host": "github.com",
                "port": 443,
                "samples": 3,
                "avg_ms": 277.03,
                "min_ms": 274.97,
                "max_ms": 280.19
            }
        }
    ]
}
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | all checks PASS |
| `1`  | at least one WARN, no FAIL |
| `2`  | at least one FAIL |
| `3`  | bad arguments (e.g. invalid port or timeout) |

This makes it usable in scripts: `net-triage host --json || echo "investigate"`.

## How it works

Each check returns a small `CheckResult` (name, verdict, summary, structured
detail), and the results roll up into one overall verdict (`FAIL` beats `WARN`
beats `PASS`):

- **DNS** — `socket.getaddrinfo`, collecting A (IPv4) and AAAA (IPv6) records and
  timing the lookup.
- **TCP** — `socket.create_connection` to each port, recording reachability and
  connect latency. A connection refused or a timeout is a `FAIL`.
- **HTTP(S)** — only when port 80/443 was reachable: a `HEAD` request via
  `http.client`. `2xx`/`3xx` is `PASS`, `4xx` is `WARN` (server answered but
  rejected the request), `5xx` is `FAIL`.
- **Latency** — several TCP connects to an open port, reported as avg/min/max.

Latency thresholds: under 200 ms is `PASS`, 200 ms to 1 s is `WARN`, and 1 s or
more is `FAIL`. If DNS fails, the remaining checks are skipped (there is nothing
to connect to).

## Limitations

- Latency is a **TCP-connect estimate**, not ICMP RTT. It is good enough for
  "is this link slow," but it is not a substitute for `ping`/`mtr` when you need
  true ICMP behavior or per-hop data.
- It checks reachability and response status, not correctness of application
  content (it does not validate page bodies, certificates beyond the default TLS
  trust store, or authentication).
- HTTP checks issue a `HEAD` request to `/`; servers that reject `HEAD` may
  report a `4xx` even when the site is otherwise healthy.
- One host per invocation.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The test suite mocks all DNS / socket / HTTP calls, so it runs fully offline and
deterministically (including in CI). No test touches the real network.

## License

MIT — see [LICENSE](LICENSE).
