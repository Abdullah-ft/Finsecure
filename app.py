# Lightweight Flask entrypoint for Vercel / WSGI
# This file exposes a Flask instance named `app` and a factory `create_app()`.
# Vercel expects one of: app.py, main.py, wsgi.py to provide `app` or `create_app()`.

from flask import Flask, jsonify

def create_app(config: dict | None = None):
    """Application factory that returns a Flask app instance.

    Args:
        config: Optional dict to update app.config for tests/runtimes.
    """
    app = Flask(__name__)

    if config:
        app.config.update(config)

    @app.get("/")
    def index():
        return jsonify({"status": "ok", "service": "Finsecure"})

    return app


# Expose a top-level `app` instance for WSGI/ASGI platforms (Vercel).
app = create_app()