# API entrypoint for Vercel.
# Vercel's Python builder will import this file and look for a WSGI/ASGI `app` object.
#
# This wrapper attempts to import your existing Flask app from common module names
# (app.py, main.py, package named `finsecure`, etc.). If it can't find one it falls
# back to a simple placeholder app so the function still responds and you can see logs.

from importlib import import_module
import sys
from flask import Flask, jsonify

app = None

candidates = [
    "app",        # app.py -> app
    "main",       # main.py -> app
    "wsgi",       # wsgi.py -> app
    "finsecure",  # package -> finsecure.app
    "src.app",    # src/app.py
    "src.main"
]

for module_name in candidates:
    try:
        m = import_module(module_name)
        maybe = getattr(m, "app", None)
        if maybe:
            app = maybe
            break
    except Exception:
        # import failed; continue to next candidate
        continue

if app is None:
    # Fallback: small informational app so you know the serverless function launched.
    fallback = Flask(__name__)

    @fallback.route("/")
    def _index():
        return (
            "Finsecure fallback: couldn't import your Flask `app` from the repository.\n"
            "Make sure your repository exposes a Flask instance named `app` in one of: app.py, main.py, wsgi.py, or a package.\n"
        )

    @fallback.route("/health")
    def _health():
        return jsonify({"status": "ok", "imported_app": False})

    app = fallback
