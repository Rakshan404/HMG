"""Routes for the intentionally non-authenticating DVR/NVR decoy."""
from flask import Blueprint, current_app, make_response, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

bp = Blueprint("dvr", __name__)
MAX_FIELD_LENGTH = 128


def _field(name):
    value = request.form.get(name, "")
    if not isinstance(value, str) or len(value) > MAX_FIELD_LENGTH or "\x00" in value:
        raise ValueError("invalid form field")
    return value.strip()


@bp.get("/")
def login_page():
    return render_template("dvr_login.html")


@bp.post("/login")
def login():
    if request.mimetype != "application/x-www-form-urlencoded":
        return _error("Invalid request.", 415)
    try:
        fields = request.form
        if not fields:
            raise ValueError("malformed or empty form")
        username = _field("username")
        password = _field("password")
    except RequestEntityTooLarge:
        return _error("Request too large.", 413)
    except (ValueError, BadRequest):
        return _error("Invalid request.", 400)

    if not username or not password or len(password) > MAX_FIELD_LENGTH:
        return _error("Invalid request.", 400, username=username[:MAX_FIELD_LENGTH])

    current_app.config["EVENT_LOGGER"](
        source_ip=request.remote_addr, user_agent=request.headers.get("User-Agent", "")[:512],
        endpoint=request.path, username=username,
    )
    return render_template("dvr_login.html", error="Login failed. Please check your credentials."), 401


def _error(message, status, username=None):
    current_app.config["EVENT_LOGGER"](
        source_ip=request.remote_addr, user_agent=request.headers.get("User-Agent", "")[:512],
        endpoint=request.path, username=username, event="invalid_input",
    )
    return render_template("dvr_login.html", error=message), status
