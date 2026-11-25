#!/usr/bin/env python3
"""Temporary guest HTTPS relay, exposed only through a project Unix socket."""
import argparse
import selectors
import socket
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer
from threading import BoundedSemaphore

REPOSITORIES = {"deb.debian.org:443", "packages.wazuh.com:443"}
SLOTS = BoundedSemaphore(8)


class Connect(StreamRequestHandler):
    def handle(self):
        if not SLOTS.acquire(blocking=False):
            return
        try:
            self.forward()
        except (OSError, ValueError):
            return
        finally:
            SLOTS.release()

    def forward(self):
        self.request.settimeout(12)
        request = self.rfile.readline(2048).decode("ascii").strip().split()
        for _ in range(20):
            header = self.rfile.readline(2048)
            if header == b"\r\n":
                break
            if not header or not header.endswith(b"\r\n"):
                return
        else:
            return
        if len(request) != 3 or request[0] != "CONNECT" or request[1] not in REPOSITORIES:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        host = request[1].split(":")[0]
        with socket.create_connection((host, 443), timeout=15) as target, selectors.DefaultSelector() as selector:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            selector.register(self.request, selectors.EVENT_READ, target)
            selector.register(target, selectors.EVENT_READ, self.request)
            while available := selector.select(timeout=60):
                for key, _ in available:
                    chunk = key.fileobj.recv(65536)
                    if not chunk:
                        return
                    key.data.sendall(chunk)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket")
    options = parser.parse_args()
    with ThreadingUnixStreamServer(options.socket, Connect) as server:
        server.daemon_threads = True
        server.serve_forever()
