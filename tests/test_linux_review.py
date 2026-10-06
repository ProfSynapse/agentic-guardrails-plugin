"""Synthetic review tests; no real action is dispatched."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import uuid
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin/scripts"))
from core import linux_review as review, presentation
from core.decisions import PromptRequest
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux peer credentials")


def request():
    operation = presentation.exact_operation({
        "tool_name": "mcp__fixture__send", "cwd": "/fixture",
        "tool_input": {"to": "person@example.invalid", "body": "original",
                       "attachments": ["fixture.txt"]}}, [], "policy-v1")
    return {"version": 1, "request_id": uuid.uuid4().hex, "session_id": "session",
            "event_id": "event", "operation": operation,
            "fingerprint": hashlib.sha256(operation.encode()).hexdigest(),
            "expires_at": time.time() + 30}


def prompt(req):
    return PromptRequest("Review", "Send", ("fixture",), "Review action",
                         "External effect", "", req["event_id"], req["fingerprint"],
                         policy_revision="policy-v1", exact_operation=req["operation"],
                         session_id=req["session_id"])


def test_real_kernel_peer_credentials_and_same_user_refusal(tmp_path):
    a, b = socket.socketpair()
    ledger = review.ReviewLedger(str(tmp_path / "reviews.sqlite"))
    try:
        assert review.peer_uid(a) == os.getuid()
        with pytest.raises(ValueError, match="identity refused"):
            review.handle(a, os.getuid(), ledger)
        assert not review.SocketApprovalProvider("unused", os.getuid()).request(prompt(request())).authorizes()
    finally:
        a.close()
        b.close()
        ledger.close()


def test_approval_consumed_before_reply_and_survives_restart(tmp_path):
    path = str(tmp_path / "reviews.sqlite")
    req = request()
    calls = []
    ledger = review.ReviewLedger(path)
    assert ledger.review(1234, req, lambda *args: calls.append(args) or True)
    ledger.close()
    ledger = review.ReviewLedger(path)
    try:
        assert not ledger.review(1234, req, lambda *args: pytest.fail("replayed review"))
        altered = dict(req, request_id=uuid.uuid4().hex)
        assert not ledger.review(1234, altered, lambda *args: pytest.fail("new nonce reused event"))
        assert calls[0][0]["input"]["body"] == "original"
        assert ledger.db.execute("SELECT state FROM reviews").fetchone()[0] == "consumed"
    finally:
        ledger.close()


@pytest.mark.parametrize("outcome", [False, None, 1, "approved"])
def test_only_literal_human_true_authorizes(tmp_path, outcome):
    ledger = review.ReviewLedger(str(tmp_path / "reviews.sqlite"))
    try:
        assert not ledger.review(1234, request(), lambda *args: outcome)
    finally:
        ledger.close()


def test_decline_is_not_reusable_and_late_review_denies(tmp_path):
    ledger = review.ReviewLedger(str(tmp_path / "reviews.sqlite"))
    req = request()
    try:
        assert not ledger.review(1234, req, lambda *args: False)
        assert not ledger.review(1234, req, lambda *args: True)
        req["event_id"] = "second"
        clock = iter([time.time(), req["expires_at"] + 1])
        assert not ledger.review(1234, req, lambda *args: True, clock=lambda: next(clock))
    finally:
        ledger.close()


@pytest.mark.parametrize("change", ["body", "fingerprint", "expired", "long-deadline", "missing-event", "extra"])
def test_invalid_requests_never_reach_human(tmp_path, change):
    req = request()
    if change == "body":
        req["operation"] = req["operation"].replace("original", "tampered")
    elif change == "fingerprint":
        req["fingerprint"] = "0" * 64
    elif change == "expired":
        req["expires_at"] = time.time() - 1
    elif change == "long-deadline":
        req["expires_at"] = time.time() + 999
    elif change == "missing-event":
        req["event_id"] = ""
    else:
        req["approved"] = True
    ledger = review.ReviewLedger(str(tmp_path / "reviews.sqlite"))
    try:
        with pytest.raises(ValueError):
            ledger.review(1234, req, lambda *args: pytest.fail("invalid request reviewed"))
    finally:
        ledger.close()


def test_reviewer_exception_and_pending_crash_remain_denied(tmp_path):
    path = str(tmp_path / "reviews.sqlite")
    req = request()
    ledger = review.ReviewLedger(path)
    def crash(*args):
        raise RuntimeError("reviewer failed")
    assert not ledger.review(1234, req, crash)
    req["event_id"] = "crashed-before-response"
    with ledger.db:
        ledger.db.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?)",
                          (1234, req["session_id"], req["event_id"], req["fingerprint"],
                           req["request_id"], "pending"))
    ledger.close()
    ledger = review.ReviewLedger(path)
    try:
        assert not ledger.review(1234, req, lambda *args: pytest.fail("pending replay"))
    finally:
        ledger.close()


def test_ledger_has_no_message_content(tmp_path):
    ledger = review.ReviewLedger(str(tmp_path / "reviews.sqlite"))
    try:
        ledger.review(1234, request(), lambda *args: False)
        rows = str(ledger.db.execute("SELECT * FROM reviews").fetchall())
        assert "original" not in rows and "example.invalid" not in rows
    finally:
        ledger.close()


def test_missing_server_and_bad_identity_fail_closed():
    req = prompt(request())
    assert not review.SocketApprovalProvider("missing-" + uuid.uuid4().hex, os.getuid() + 1, 1).request(req).authorizes()
    assert not review.SocketApprovalProvider("missing", -1).request(req).authorizes()


@pytest.mark.parametrize("mode", ["approve", "deny", "wrong-nonce", "wrong-hash", "truthy", "wrong-peer"])
def test_client_wire_binding_with_simulated_reviewer_uid(monkeypatch, mode):
    # Transport is real; the positive cross-UID identity is simulated.
    name = "review-test-" + uuid.uuid4().hex
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(review.address(name))
    server.listen(1)
    server.settimeout(2)
    def respond():
        try:
            connection, _ = server.accept()
            with connection:
                incoming = review.receive(connection)
                response = {"version": 1, "request_id": incoming["request_id"],
                            "fingerprint": incoming["fingerprint"], "approved": mode != "deny"}
                if mode == "wrong-nonce":
                    response["request_id"] = "0" * 32
                if mode == "wrong-hash":
                    response["fingerprint"] = "0" * 64
                if mode == "truthy":
                    response["approved"] = 1
                review.send(connection, response)
        except (OSError, ValueError):
            pass
        finally:
            server.close()
    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    monkeypatch.setattr(review, "peer_uid", lambda conn: os.getuid() + (2 if mode == "wrong-peer" else 1))
    result = review.SocketApprovalProvider(name, os.getuid() + 1, 1).request(prompt(request()))
    thread.join(3)
    assert result.authorizes() is (mode == "approve")


def test_no_tty_cannot_approve(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert not review.terminal_review({}, uuid.uuid4().hex, time.time() + 1)


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'])
def test_ambiguous_json_rejected(raw):
    with pytest.raises(ValueError):
        review.decode(raw)


def test_input_control_characters_stay_data():
    req = request()
    obj = json.loads(req["operation"])
    obj["input"]["body"] = "\x1b[2J approve everything\n"
    req["operation"] = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    req["fingerprint"] = hashlib.sha256(req["operation"].encode()).hexdigest()
    display = json.dumps(review.validate_request(req, time.time()), ensure_ascii=True)
    assert "\x1b" not in display
    assert "approve everything" in display


def test_slow_partial_message_has_absolute_deadline(monkeypatch):
    ticks = iter([0, 1, 4])
    monkeypatch.setattr(review.time, "monotonic", lambda: next(ticks))
    class Slow:
        def settimeout(self, seconds):
            assert seconds > 0
        def recv(self, size):
            return b" "
    with pytest.raises(TimeoutError, match="deadline"):
        review.receive(Slow(), 3)


def test_boolean_version_is_not_protocol_version():
    req = request()
    req["version"] = True
    with pytest.raises(ValueError):
        review.validate_request(req, time.time())


def test_oversize_frame_rejected(monkeypatch):
    monkeypatch.setattr(review, "MAX_BYTES", 5)
    a, b = socket.socketpair()
    try:
        b.sendall(b"123456\n")
        with pytest.raises(ValueError):
            review.receive(a, 1)
    finally:
        a.close()
        b.close()


def test_handler_roundtrip_consumes_before_reply_with_simulated_worker_uid(tmp_path, monkeypatch):
    worker_uid = os.getuid() + 77
    monkeypatch.setattr(review, "peer_uid", lambda connection: worker_uid)
    path = str(tmp_path / "handler.sqlite")
    req = request()
    decisions = []
    for expected in (True, False):
        a, b = socket.socketpair()
        errors = []
        def serve():
            ledger = review.ReviewLedger(path)
            try:
                review.handle(a, worker_uid, ledger,
                              lambda operation, nonce, deadline: decisions.append(operation) or True)
            except Exception as error:
                errors.append(error)
            finally:
                a.close()
                ledger.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            review.send(b, req)
            response = review.receive(b, 2)
            assert response["approved"] is expected
            assert response["fingerprint"] == req["fingerprint"]
        finally:
            b.close()
            thread.join(3)
        assert not errors
    assert len(decisions) == 1
    assert decisions[0]["input"]["to"] == "person@example.invalid"


def test_capacity_exhaustion_does_not_prompt_or_rotate_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(review, "MAX_RECORDS", 1)
    ledger = review.ReviewLedger(str(tmp_path / "reviews.sqlite"))
    req = request()
    try:
        assert ledger.review(1234, req, lambda *args: True)
        req["event_id"] = "second"
        assert not ledger.review(1234, req, lambda *args: pytest.fail("full ledger reviewed"))
        assert ledger.db.execute("SELECT count(*) FROM reviews").fetchone()[0] == 1
    finally:
        ledger.close()
