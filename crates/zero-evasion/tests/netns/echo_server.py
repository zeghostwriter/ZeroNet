#!/usr/bin/env python3
"""Echo whatever the kernel hands the application on port 443, and log it.
Usage: echo_server.py LOGFILE REAL_NAME DECOY_NAME"""
import json
import socket
import threading

import sys

log, real, decoy = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 443))
srv.listen(16)
out = open(log, "a", buffering=1)


def serve(conn):
    got = b""
    while True:
        data = conn.recv(65535)
        if not data:
            break
        got += data
        conn.sendall(data)
    out.write(json.dumps({"received": len(got), "has_real": real in got, "has_decoy": decoy in got}) + "\n")


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
