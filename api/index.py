# api/index.py
# Vercel entrypoint for a Flask app.
# This wrapper attempts to import your app from a variety of common module names
# and patterns. It prints detailed tracebacks to stdout/stderr so they appear
# in Vercel logs and you can diagnose why import failed.
#
# Usage:
# - If your project exposes `app` (a Flask instance) in app.py, main.py, wsgi.py,
#   or in a package's __init__.py, this wrapper should find it.
# - If your project uses the application factory pattern, e.g. create_app(), this
#   wrapper will try to call create_app() with no args.
#
# After replacing this file, deploy and then check Vercel's function logs for
# printed tracebacks if it still falls back.

from importlib import import_module
import traceback
import sys
import os
from flask import Flask, jsonify

# Candidate module names to try importing from your repo.
candidates = [
    "app",          # app.py -> app
    "main",         # main.py -> app
    "wsgi",         # wsgi.py -> app
    "server",       # server.py -> app
    "run",          # run.py -> app
    "finsecure",    # package finsecure -> finsecure.app or finsecure.create_app
    "src.app",
    "src.main",
    "src.wsgi",
    # Add more candidates if your project uses a different layout
]

# We'll collect all errors so they are visible in logs
errors = {}
app = None
imported_from = None

def try_import_module(name):
    try:
        return import_module(name)
    except Exception:
        errors[name] = traceback.format_exc()
        return None

for mod_name in candidates:
    m = try_import_module(mod_name)
    if not m:
        continue

    # 1) look for 'app' or 'application' attribute
    maybe = getattr(m, "app", None) or getattr(m, "application", None)
    if maybe:
        app = maybe
        imported_from = f"{mod_name}.app"
        break

    # 2) look for a create_app factory and call it (no args)
    create = getattr(m, "create_app", None)
    if create and callable(create):
        try:
            app = create()
            imported_from = f"{mod_name}.create_app()"
            break
        except Exception:
            # save traceback for this attempt and continue to next candidate
            key = f"{mod_name}.create_app()"
            errors[key] = traceback.format_exc()
            continue

# If still not found, attempt to import package attribute finsecure.app pattern
if app is None:
    # try finsecure.__init__ exposing app
    try:
        m = import_module("finsecure")
        maybe = getattr(m, "app", None)
        if maybe:
            app = maybe
            imported_from = "finsecure.app"
    except Exception:
        errors["finsecure"] = traceback.format_exc()

# If we've found an app, print where it came from for logs
if app is not None:
    print(f"[vercel] Imported Flask app from: {imported_from}", file=sys.stdout)
else:
    # Print all errors to help debugging in the Vercel logs
    print("[vercel] Failed to import Flask app. Import attempts and tracebacks follow:", file=sys.stderr)
    for k, v in errors.items():
        print(f"--- Attempt: {k} ---", file=sys.stderr)
        print(v, file=sys.stderr)
    # Define a fallback informational app so the function responds
    fallback = Flask(__name__)

    @fallback.route("/")
    def _index():
        return (
            "Finsecure fallback: couldn't import your Flask `app` from the repository.\n"
            "Make sure the repository exposes a Flask instance named `app` in one of: app.py, main.py, wsgi.py,\n"
            "or exposes a create_app() factory that returns a Flask app.\n\n"
            "Check Vercel function logs for import tracebacks."
        )

    @fallback.route("/health")
    def _health():
        return jsonify({"status": "ok", "imported_app": False, "attempts": list(errors.keys())})

    app = fallback
