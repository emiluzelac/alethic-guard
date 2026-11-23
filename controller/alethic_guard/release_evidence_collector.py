"""Staging HTTPS receiver for canonical Alethic release qualification records."""

import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import sqlite3
import ssl
import uuid
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ENDPOINT = "/v1/release-evidence"
MAX_RECORD = 512
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")


def _record_digest(body):
    try:
        record = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if (
        type(record) is not dict
        or set(record) != {"artifact_sha256", "commit", "verdict", "version"}
        or type(record["version"]) is not int
        or record["version"] != 1
        or record["verdict"] not in ("pass", "fail")
        or type(record["artifact_sha256"]) is not str
        or not re.fullmatch(r"[a-f0-9]{64}", record["artifact_sha256"])
        or type(record["commit"]) is not str
        or not re.fullmatch(r"[a-f0-9]{40}", record["commit"])
        or body != json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    ):
        return None
    return hashlib.sha256(body).hexdigest()


def _valid_key(value):
    try:
        key = uuid.UUID(value)
    except ValueError:
        return False
    return key.version == 4 and str(key) == value


class _Server(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        if self.tls:
            try:
                connection = self.tls.wrap_socket(connection, server_side=True)
            except OSError:
                connection.close()
                raise
        return connection, address

    def database(self):
        connection = sqlite3.connect(self.database_path, timeout=2)
        connection.execute("PRAGMA synchronous=FULL")
        return connection


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _header(self, name):
        values = self.headers.get_all(name, [])
        return values[0] if len(values) == 1 else ""

    def _authorized(self, token):
        value = self._header("Authorization").encode("latin-1")
        return hmac.compare_digest(value, b"Bearer " + token)

    def _reply(self, status, key=None, digest=None):
        self.close_connection = True
        body = (
            json.dumps({"idempotency_key": key, "payload_sha256": digest},
                       separators=(",", ":")).encode()
            if key is not None else b""
        )
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if body:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != ENDPOINT:
            return self._reply(404)
        if not self._authorized(self.server.writer):
            return self._reply(401)
        key = self._header("Idempotency-Key")
        size = self._header("Content-Length")
        if (
            not _valid_key(key)
            or self._header("Content-Type") != "application/json"
            or "Transfer-Encoding" in self.headers
            or not re.fullmatch(r"[1-9][0-9]{0,2}", size)
            or int(size) > MAX_RECORD
        ):
            return self._reply(400)
        body = self.rfile.read(int(size))
        digest = _record_digest(body) if len(body) == int(size) else None
        if digest is None:
            return self._reply(400)
        with closing(self.server.database()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT body FROM receipts WHERE key=?", (key,)).fetchone()
            if row is None:
                connection.execute("INSERT INTO receipts VALUES (?, ?, ?)", (key, body, digest))
        if row is not None and row[0] != body:
            return self._reply(409)
        # Closing the transaction before sending the reply makes receipt lookup
        # independent of whether the writer gets its response.
        self._reply(201 if row is None else 200, key, digest)

    def do_GET(self):
        prefix = ENDPOINT + "/"
        key = self.path.removeprefix(prefix)
        if not self.path.startswith(prefix) or not _valid_key(key):
            return self._reply(404)
        if not self._authorized(self.server.reader):
            return self._reply(401)
        with closing(self.server.database()) as connection:
            row = connection.execute("SELECT digest FROM receipts WHERE key=?", (key,)).fetchone()
        if row is None:
            return self._reply(404)
        self._reply(200, key, row[0])


def make_server(address, database, writer, reader, tls=None):
    if not TOKEN.fullmatch(writer) or not TOKEN.fullmatch(reader) or writer == reader:
        raise ValueError("collector requires distinct scoped credentials")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS receipts (key TEXT PRIMARY KEY, body BLOB NOT NULL,"
            " digest TEXT NOT NULL)"
        )
    server_type = type("_IPv6Server", (_Server,), {"address_family": socket.AF_INET6}) if (
        ":" in address[0]
    ) else _Server
    server = server_type(address, _Handler)
    server.database_path = database
    server.writer = writer.encode("ascii")
    server.reader = reader.encode("ascii")
    server.tls = tls
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--writer-token-file", type=Path, required=True)
    parser.add_argument("--reader-token-file", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    with make_server(
        (args.host, args.port), args.database,
        args.writer_token_file.read_text("ascii").rstrip("\n"),
        args.reader_token_file.read_text("ascii").rstrip("\n"), tls,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
