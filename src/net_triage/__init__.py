"""net-triage: a small CLI for triaging host reachability.

Checks DNS resolution, TCP port reachability, HTTP(S) status, and a
TCP-connect-based round-trip latency estimate, then prints a clean report
(text or JSON) with a PASS/WARN/FAIL verdict per check.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
