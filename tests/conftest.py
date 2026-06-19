"""Shared test helpers.

Every test mocks the network seams in ``net_triage.checks`` so the suite is
fully offline and deterministic. Nothing here opens a real socket.
"""

import socket

import pytest


class FakeSocket:
    """Minimal stand-in for a connected socket; only needs close()."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def fake_socket():
    return FakeSocket()


def make_addrinfo(ipv4=("93.184.216.34",), ipv6=("2606:2800:220:1:248:1893:25c8:1946",)):
    """Build a getaddrinfo-style list of tuples for the given addresses."""
    infos = []
    for addr in ipv4:
        infos.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, 0)))
    for addr in ipv6:
        infos.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, 0, 0, 0)))
    return infos
