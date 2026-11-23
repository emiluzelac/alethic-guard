"""Controlled TLS endpoint for Guard qualification on a disconnected lab network."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import ssl
import time
import uuid


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def trace(self):
        if self.server.trace:
            with self.server.trace.open("a") as output:
                output.write(json.dumps({"method": self.command, "path": self.path}) + "\n")

    def do_GET(self):
        self.trace()
        self.send_error(404)

    def do_POST(self):
        self.trace()
        if self.path != "/v1/fixture":
            self.send_error(404)
            return
        try:
            key = str(uuid.UUID(self.headers["Idempotency-Key"]))
            size = int(self.headers["Content-Length"])
            if size > 512 or size < 1:
                raise ValueError("bad size")
        except (KeyError, ValueError, TypeError):
            self.send_error(400)
            return
        data = self.rfile.read(size)
        if data != b'{"kind":"alethic-guard-synthetic","value":1}':
            self.send_error(422)
            return
        if self.server.response == "redirect":
            self.send_response(307)
            self.send_header("Location", "/v1/redirect-target")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        digest = hashlib.sha256(data).hexdigest()
        result = {"idempotency_key": key, "payload_sha256": digest}
        receipt = self.server.receipts / f"{key}.json"
        try:
            with receipt.open("x") as output:
                json.dump(result, output)
            code = 201
        except FileExistsError:
            if json.loads(receipt.read_text()) != result:
                self.send_error(409)
                return
            code = 200
        self.server.pause_at("receipt")
        if self.server.response == "disconnect":
            self.close_connection = True
            return
        encoded = json.dumps(result).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)


class Collector(HTTPServer):
    address_family = socket.AF_INET6

    def pause_at(self, phase):
        if self.phase != phase:
            return
        self.barrier.with_suffix(".ready").write_text(str(time.time_ns()))
        deadline = time.monotonic() + 15
        while not self.barrier.with_suffix(".continue").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError(f"lab barrier expired at {phase}")
            time.sleep(0.01)

    def get_request(self):
        client, address = super().get_request()
        try:
            client.settimeout(18)
            self.pause_at("handshake")
            return self.context.wrap_socket(client, server_side=True), address
        except Exception:
            client.close()
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int)
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("output", type=Path)
    parser.add_argument("--phase", choices=("handshake", "receipt"))
    parser.add_argument("--barrier", type=Path)
    parser.add_argument("--response", choices=("receipt", "redirect", "disconnect"), default="receipt")
    parser.add_argument("--trace", type=Path)
    args = parser.parse_args()
    if bool(args.phase) != bool(args.barrier):
        parser.error("--phase and --barrier must be used together")
    with Collector(("::", args.port), Handler) as server:
        server.receipts = args.output
        server.phase = args.phase
        server.barrier = args.barrier
        server.response = args.response
        server.trace = args.trace
        server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.context.load_cert_chain(args.cert, args.key)
        server.serve_forever()
