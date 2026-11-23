"""Controlled TLS endpoint for Guard qualification on a disconnected lab network."""

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import ssl
import sys
import uuid


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
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
        encoded = json.dumps(result).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)


class Collector(HTTPServer):
    address_family = socket.AF_INET6


if __name__ == "__main__":
    port, cert, key, output = sys.argv[1:]
    with Collector(("::", int(port)), Handler) as server:
        server.receipts = Path(output)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
