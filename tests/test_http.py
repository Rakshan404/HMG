
import json
from datetime import datetime

from decoys.http import logger as http_logger
from decoys.http.app import create_app
from decoys.http.logger import log_event


def test_login_page_delivery_and_security_headers():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Content-Security-Policy"]


def test_login_post_logs_metadata_and_fails(caplog):
    app = create_app({"TESTING": True})
    client = app.test_client()

    with caplog.at_level("INFO", logger="hmg.http"):
        response = client.post(
            "/login",
            data={"username": "operator", "password": "test12345"}
        )

    assert response.status_code == 401

    event = json.loads(caplog.records[-1].message)
    assert event["event"] == "login_attempt"
    assert event["honeypot"] == "HTTP"
    assert event["details"]["username"] == "operator"
    assert "password" not in event["details"]


def test_logger_json_is_utc_and_password_free(caplog):
    with caplog.at_level("INFO", logger="hmg.http"):
        log_event(
            source_ip="127.0.0.1",
            user_agent="test-agent",
            endpoint="/login",
            username="operator"
        )

    event = json.loads(caplog.records[-1].message)
    stamp = datetime.fromisoformat(event["timestamp"])

    assert stamp.tzinfo is not None
    assert stamp.utcoffset().total_seconds() == 0
    assert event["source_ip"] == "127.0.0.1"
    assert event["honeypot"] == "HTTP"
    assert event["details"]["user_agent"] == "test-agent"
    assert "password" not in json.dumps(event)


def test_crlf_cannot_forge_log_records(caplog):
    with caplog.at_level("INFO", logger="hmg.http"):
        log_event(
            source_ip="127.0.0.1",
            user_agent="ua\r\nforged",
            endpoint="/login",
            username="u\nforged"
        )

    assert len(caplog.records) == 1

    event = json.loads(caplog.records[0].message)

    assert event["details"]["user_agent"] == "ua\r\nforged"
    assert event["details"]["username"] == "u\nforged"


def test_events_persist_as_appended_jsonl_without_passwords(
    tmp_path, monkeypatch, caplog
):
    event_path = tmp_path / "data" / "http_events.jsonl"
    monkeypatch.setattr(http_logger, "EVENTS_FILE", event_path)

    with caplog.at_level("INFO", logger="hmg.http"):
        log_event(
            source_ip="127.0.0.1",
            user_agent="agent",
            endpoint="/login",
            username="operator"
        )

        log_event(
            source_ip="127.0.0.2",
            user_agent="agent2",
            endpoint="/login",
            username="second"
        )

    assert event_path.parent.is_dir()

    lines = event_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    events = [json.loads(line) for line in lines]

    assert [event["details"]["username"] for event in events] == [
        "operator",
        "second"
    ]

    assert events[0]["event_id"] == "EVT-001"
    assert events[1]["event_id"] == "EVT-002"

    for event in events:
        assert set(event.keys()) == {
            "event_id",
            "timestamp",
            "source_ip",
            "source_mac",
            "honeypot",
            "event",
            "details"
        }
        assert event["honeypot"] == "HTTP"
        assert "password" not in json.dumps(event)


def test_xss_username_is_not_reflected_as_executable_html():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "<script>alert(1)</script>",
            "password": "test123"
        }
    )

    assert response.status_code == 401
    assert b"<script>alert(1)</script>" not in response.data


def test_unsupported_content_type_rejected():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.post(
        "/login",
        data='{"username":"admin"}',
        content_type="application/json"
    )

    assert response.status_code in (400, 415)


def test_malformed_form_rejected_safely():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.post(
        "/login",
        data=b"\xff\xfe",
        content_type="application/x-www-form-urlencoded"
    )

    assert response.status_code in (400, 401)


def test_oversized_request_rejected():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.post(
        "/login",
        data={"username": "a" * 5000, "password": "test"},
    )

    assert response.status_code == 413


def test_empty_and_oversized_usernames_rejected():
    app = create_app({"TESTING": True})
    client = app.test_client()

    empty_response = client.post(
        "/login",
        data={"username": "", "password": "test"}
    )

    oversized_response = client.post(
        "/login",
        data={"username": "a" * 300, "password": "test"}
    )

    assert empty_response.status_code in (400, 401)
    assert oversized_response.status_code in (400, 401)


def test_debug_disabled_and_default_network_config():
    import config

    assert config.DEBUG is False
    assert config.HOST == "127.0.0.1"
    assert config.PORT == 8080
