"""Linux cross-UID human review. Opt-in prototype; never executes an action.

A foreground owner terminal reviews complete JSON operations. Linux SO_PEERCRED
authenticates both ends of an abstract Unix socket. The SQLite ledger consumes
a host event before responding, so retries/crashes never replay an approval.
This guards review issuance, not exactly-once downstream execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import select
import socket
import sqlite3
import struct
import sys
import time
import uuid

MAX_BYTES = 262144
MAX_SECONDS = 100
MAX_RECORDS = 10000


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))


def address(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
        raise ValueError("invalid review socket name")
    return "\0" + name


def peer_uid(connection):
    if sys.platform != "linux":
        raise ValueError("Linux peer credentials required")
    return struct.unpack("3i", connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]


def receive(connection, timeout_s=MAX_SECONDS):
    data = bytearray()
    deadline = time.monotonic() + timeout_s
    while len(data) <= MAX_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("review message deadline exceeded")
        connection.settimeout(remaining)
        part = connection.recv(min(4096, MAX_BYTES + 1 - len(data)))
        if not part:
            raise ValueError("incomplete review message")
        data.extend(part)
        if b"\n" in part:
            line, rest = bytes(data).split(b"\n", 1)
            if rest or len(line) > MAX_BYTES:
                raise ValueError("invalid review framing")
            return decode(line.decode("utf-8"))
    raise ValueError("review message too large")


def send(connection, value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                     separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_BYTES:
        raise ValueError("review message too large")
    connection.sendall(raw + b"\n")


def validate_request(value, now):
    fields = {"version", "request_id", "session_id", "event_id", "fingerprint",
              "operation", "expires_at"}
    if not isinstance(value, dict) or set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("invalid review request")
    for key in ("session_id", "event_id"):
        if not isinstance(value[key], str) or not 1 <= len(value[key]) <= 256:
            raise ValueError("host identity required")
    if not isinstance(value["request_id"], str) or not re.fullmatch(
            r"[0-9a-f]{32}", value["request_id"]):
        raise ValueError("invalid request identity")
    if not isinstance(value["fingerprint"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", value["fingerprint"]):
        raise ValueError("invalid operation fingerprint")
    operation = value["operation"]
    if not isinstance(operation, str):
        raise ValueError("complete operation required")
    obj = decode(operation)
    if (not isinstance(obj, dict) or set(obj) !=
            {"tool", "cwd", "input", "events", "policy_revision"}
            or not isinstance(obj["tool"], str) or not obj["tool"]
            or not isinstance(obj["input"], dict)
            or not isinstance(obj["policy_revision"], str) or not obj["policy_revision"]
            or not isinstance(obj["events"], list)
            or not isinstance(obj["cwd"], str)):
        raise ValueError("invalid operation envelope")
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False)
    if canonical != operation or hashlib.sha256(operation.encode()).hexdigest() != value["fingerprint"]:
        raise ValueError("operation does not match fingerprint")
    deadline = value["expires_at"]
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not now < deadline <= now + MAX_SECONDS):
        raise ValueError("review expired or deadline invalid")
    return obj


class ReviewLedger:
    """Owned by the reviewer account, not readable/writable by the worker."""
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=2)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS reviews (
            worker INTEGER, session TEXT, event TEXT, fingerprint TEXT,
            request TEXT, state TEXT, PRIMARY KEY(worker,session,event))""")
        self.db.commit()

    def review(self, worker, request, reviewer, clock=time.time):
        operation = validate_request(request, clock())
        key = (worker, request["session_id"], request["event_id"])
        try:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                if self.db.execute("SELECT count(*) FROM reviews").fetchone()[0] >= MAX_RECORDS:
                    return False
                self.db.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?)",
                                key + (request["fingerprint"], request["request_id"], "pending"))
        except sqlite3.IntegrityError:
            return False
        approved = False
        try:
            approved = reviewer(operation, request["request_id"], request["expires_at"]) is True
        except Exception:
            approved = False
        approved = approved and clock() < request["expires_at"]
        # Commit before replying: lost response / process restart cannot reissue.
        with self.db:
            changed = self.db.execute(
                "UPDATE reviews SET state=? WHERE worker=? AND session=? AND event=? AND state='pending'",
                ("consumed" if approved else "denied",) + key).rowcount
        return approved and changed == 1

    def close(self):
        self.db.close()


def terminal_review(operation, request_id, expires_at):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    # ASCII JSON escapes terminal controls; no truncation and no content logged.
    print("\nUNTRUSTED ACTION DATA — review all arguments below.")
    print(json.dumps(operation, ensure_ascii=True, sort_keys=True, indent=2))
    print("This approves one hook invocation, not a reusable permission.")
    # Generate the terminal challenge here, never from worker-supplied identity.
    # A worker must not be able to repeat a previous prompt's approval phrase.
    phrase = "approve " + uuid.uuid4().hex[:12]
    remaining = max(0, expires_at - time.time())
    print("Confirm within %d seconds. Paste this exact phrase, then press Enter:" % remaining)
    print(phrase, flush=True)
    print("Or press Enter on an empty line to decline.", flush=True)
    if not select.select([sys.stdin], [], [], remaining)[0]:
        print("EXPIRED. No approval was granted. Restart the worker test for a new request.", flush=True)
        return False
    accepted = sys.stdin.readline().strip() == phrase
    print("Approval phrase accepted." if accepted else
          "DECLINED. The submitted line did not match this request's phrase.", flush=True)
    return accepted


def handle(connection, worker_uid, ledger, reviewer=terminal_review):
    actual = peer_uid(connection)
    # Same-account operation is never an authentication boundary.
    if actual != worker_uid or actual == os.getuid():
        raise ValueError("review worker identity refused")
    connection.settimeout(MAX_SECONDS)
    request = receive(connection, 10)
    approved = ledger.review(actual, request, reviewer)
    print("APPROVED: one review granted." if approved else
          "DENIED: no approval granted (declined, expired or already used).", flush=True)
    send(connection, {"version": 1, "request_id": request["request_id"],
                      "fingerprint": request["fingerprint"], "approved": approved})


class SocketApprovalProvider:
    def __init__(self, name, reviewer_uid, timeout_s=90):
        self.name = name
        self.reviewer_uid = reviewer_uid
        self.timeout_s = min(MAX_SECONDS - 1, max(1, timeout_s))

    def request(self, prompt):
        from .approvals import ApprovalResponse
        try:
            if (sys.platform != "linux" or type(self.reviewer_uid) is not int
                    or self.reviewer_uid < 0 or self.reviewer_uid == os.getuid()):
                return ApprovalResponse(False, "provider-unavailable", "review:identity")
            operation = prompt.exact_operation
            request = {"version": 1, "request_id": uuid.uuid4().hex,
                       "session_id": prompt.session_id, "event_id": prompt.event_id,
                       "fingerprint": prompt.operation_fingerprint,
                       "operation": operation, "expires_at": time.time() + self.timeout_s}
            validate_request(request, time.time())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_s)
                connection.connect(address(self.name))
                if peer_uid(connection) != self.reviewer_uid:
                    return ApprovalResponse(False, "provider-unavailable", "review:peer")
                send(connection, request)
                response = receive(connection, self.timeout_s)
            if (not isinstance(response, dict) or set(response) !=
                    {"version", "request_id", "fingerprint", "approved"}
                    or type(response["version"]) is not int or response["version"] != 1
                    or response["request_id"] != request["request_id"]
                    or response["fingerprint"] != request["fingerprint"]
                    or type(response["approved"]) is not bool
                    or time.time() >= request["expires_at"]):
                return ApprovalResponse(False, "invalid-response")
            return ApprovalResponse(response["approved"],
                                    "approved" if response["approved"] else "denied")
        except Exception:
            return ApprovalResponse(False, "provider-error", "review:unavailable")


def main():
    parser = argparse.ArgumentParser(description="Foreground Linux owner review terminal (experimental)")
    parser.add_argument("--name", required=True, help="abstract Unix socket name")
    parser.add_argument("--worker-uid", required=True, type=int)
    parser.add_argument("--ledger", required=True, help="new private SQLite file in owner-only directory")
    args = parser.parse_args()
    if (sys.platform != "linux" or args.worker_uid <= 0 or args.worker_uid == os.getuid()
            or not sys.stdin.isatty() or not sys.stdout.isatty()):
        parser.error("requires Linux, a distinct unprivileged worker UID and an owner terminal")
    # A trusted owner-only parent protects ledger, journal and SQLite sidecars.
    parent = os.path.dirname(os.path.abspath(args.ledger))
    info = os.stat(parent)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        parser.error("ledger parent must be owned by reviewer with mode 0700")
    if os.path.lexists(args.ledger):
        info = os.lstat(args.ledger)
        import stat
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            parser.error("existing ledger must be a private regular file owned by reviewer")
    os.umask(0o077)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(address(args.name))
        server.listen(4)
        ledger = ReviewLedger(args.ledger)
        try:
            print("Guardrails owner review ready. Ctrl-C stops review; pending calls deny.", flush=True)
            while True:
                connection, _ = server.accept()
                with connection:
                    try:
                        handle(connection, args.worker_uid, ledger)
                    except Exception:
                        # Never echo untrusted payloads or exception details.
                        print("Review request refused or unavailable.", flush=True)
        finally:
            ledger.close()


if __name__ == "__main__":
    main()
