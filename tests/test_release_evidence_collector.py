import hashlib
import http.client
import json
import threading
import uuid

from alethic_guard.release_evidence_collector import make_server

WRITER = "w" * 32
READER = "r" * 32
PATH = "/v1/release-evidence"
RECORD = b'{"artifact_sha256":"' + b"a" * 64 + b'","commit":"' + b"b" * 40 + b'","verdict":"pass","version":1}'


def test_scoped_durable_receipts(tmp_path):
    database = tmp_path / "collector.sqlite3"
    key = str(uuid.uuid4())

    def exchange(server, method, token, body=None):
        headers = {"Authorization": f"Bearer {token}"}
        path = f"{PATH}/{key}"
        if method == "POST":
            headers.update({"Content-Type": "application/json", "Idempotency-Key": key})
            path = PATH
        client = http.client.HTTPConnection(*server.server_address, timeout=2)
        try:
            client.request(method, path, body, headers)
            response = client.getresponse()
            return response.status, response.read()
        finally:
            client.close()

    def exercise(check):
        with make_server(("127.0.0.1", 0), database, WRITER, READER) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                check(server)
            finally:
                server.shutdown()
                thread.join()

    def initial(server):
        assert exchange(server, "POST", READER, RECORD)[0] == 401
        assert exchange(server, "POST", WRITER, RECORD + b"\n")[0] == 400
        assert exchange(server, "GET", READER)[0] == 404
        status, receipt = exchange(server, "POST", WRITER, RECORD)
        assert status == 201
        assert json.loads(receipt) == {
            "idempotency_key": key, "payload_sha256": hashlib.sha256(RECORD).hexdigest()
        }
        assert exchange(server, "POST", WRITER, RECORD) == (200, receipt)
        assert exchange(server, "POST", WRITER, RECORD.replace(b"pass", b"fail"))[0] == 409
        assert exchange(server, "GET", WRITER)[0] == 401
        assert exchange(server, "GET", READER) == (200, receipt)

    def restarted(server):
        status, receipt = exchange(server, "GET", READER)
        assert status == 200
        assert json.loads(receipt)["payload_sha256"] == hashlib.sha256(RECORD).hexdigest()
        assert exchange(server, "POST", WRITER, RECORD) == (200, receipt)

    exercise(initial)
    exercise(restarted)
