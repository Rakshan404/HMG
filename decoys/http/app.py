"""Local-only Flask entry point for the HTTP DVR/NVR honeypot."""
from flask import Flask
import config
from decoys.http.logger import log_event
from decoys.http.routes import bp


def create_app(test_config=None):
    app = Flask(__name__, template_folder="../../templates", static_folder="../../static")
    app.config.update(MAX_CONTENT_LENGTH=4096, EVENT_LOGGER=log_event)
    if test_config:
        app.config.update(test_config)
    app.register_blueprint(bp)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    return app


if __name__ == "__main__":
    create_app().run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
