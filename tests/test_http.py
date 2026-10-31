import json
from datetime import datetime, timezone

import config
from decoys.http.app import create_app
from decoys.http.logger import log_event


def setup_app():
    events = []
    app = create_app({"TESTING": True, "EVENT_LOGGER": lambda **event: events.append(event)})
    return app, events


def test_login_page_delivery_and_security_headers():
    app, _ = setup_app()
    response = app.test_client().get("/")
    assert response.status_code == 200
    assert b"NETWORK VIDEO RECORDER" in response.data
    assert b'type="password"' in response.data
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_login_post_logs_metadata_and_fails():
    app, events = setup_app()
    response = app.test_client().post("/login", data={"username": "operator", "password": "do-not-log"}, headers={"User-Agent": "test-agent"})
    assert response.status_code == 401
    assert b"Login failed" in response.data
    assert events == [{"source_ip": "127.0.0.1", "user_agent": "test-agent", "endpoint": "/login", "username": "operator"}]
    assert "do-not-log" not in json.dumps(events)


def test_logger_json_is_utc_and_password_free(caplog):
    with caplog.at_level("INFO", logger="hmg.http"):
        log_event(source_ip="127.0.0.1", user_agent="test-agent", endpoint="/login", username="operator")
    event = json.loads(caplog.records[-1].message)
    stamp = datetime.fromisoformat(event["timestamp"])
    assert stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0
    assert event["source_ip"] == "127.0.0.1"
    assert event["user_agent"] == "test-agent"
    assert event["endpoint"] == "/login"
    assert event["username"] == "operator"
    assert "password" not in event


def test_crlf_cannot_forge_log_records(caplog):
    with caplog.at_level("INFO", logger="hmg.http"):
        log_event(source_ip="127.0.0.1", user_agent="ua\r\nforged", endpoint="/login", username="u\nforged")
    assert len(caplog.records) == 1
    event = json.loads(caplog.records[0].message)
    assert event["user_agent"] == "ua\r\nforged"
    assert event["username"] == "u\nforged"


def test_xss_username_is_not_reflected_as_executable_html():
    app, _ = setup_app()
    payload = '<script>alert(1)</script>'
    response = app.test_client().post("/login", data={"username": payload, "password": "secret"})
    assert response.status_code == 401
    assert payload.encode() not in response.data
    assert b"&lt;script&gt;" not in response.data


def test_unsupported_content_type_rejected():
    app, _ = setup_app()
    response = app.test_client().post("/login", json={"username": "x", "password": "y"})
    assert response.status_code == 415
    assert b"Invalid request" in response.data
    assert b"Traceback" not in response.data


def test_malformed_form_rejected_safely():
    app, _ = setup_app()
    response = app.test_client().post("/login", data="not=form%ZZ", content_type="application/x-www-form-urlencoded")
    assert response.status_code == 400
    assert b"Traceback" not in response.data
    assert b"Internal Server Error" not in response.data


def test_oversized_request_rejected():
    app, _ = setup_app()
    response = app.test_client().post("/login", data={"username": "u" * 5000, "password": "x"})
    assert response.status_code == 413


def test_empty_and_oversized_usernames_rejected():
    app, _ = setup_app()
    client = app.test_client()
    assert client.post("/login", data={"username": "", "password": "x"}).status_code == 400
    assert client.post("/login", data={"username": "u" * 129, "password": "x"}).status_code == 400


def test_debug_disabled_and_default_network_config():
    app, _ = setup_app()
    assert app.debug is False
    assert config.HOST == "127.0.0.1"
    assert config.PORT == 8080
    assert config.DEBUG is False
