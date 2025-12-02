# wsgi.py - single entrypoint that exposes a Flask `app` object.
# Place this file at the repository root and push to GitHub.
#
# The file tries common module names (app.py, main.py, package, etc.)
# and either grabs `app`/`application` or calls create_app() if present.
# If nothing is found it raises a clear RuntimeError (which will appear
# in Vercel function logs) describing what was attempted.

from importlib import import_module
import traceback
import sys

candidates = [
    "app", "main", "wsgi", "server", "run", "finsecure",
    "src.app", "src.main", "finsecure.__init__"
]

_app = None
errors = {}

def try_import(name):
    try:
        return import_module(name)
    except Exception as e:
        errors[name] = traceback.format_exc()
        return None

for mod_name in candidates:
    mod = try_import(mod_name)
    if not mod:
        continue

    # 1. Direct app/application attribute
    _maybe = getattr(mod, "app", None) or getattr(mod, "application", None)
    if _maybe:
        _app = _maybe
        source = f"{mod_name}.app"
        break

    # 2. create_app factory
    create = getattr(mod, "create_app", None)
    if callable(create):
        try:
            _app = create()
            source = f"{mod_name}.create_app()"
            break
        except Exception:
            errors[f"{mod_name}.create_app()"] = traceback.format_exc()
            continue

if _app is None:
    # Print detailed errors to stdout/stderr for debugging in Vercel logs
    print("[wsgi] Failed to locate Flask app. Attempts and tracebacks follow:", file=sys.stderr)
    for k, v in errors.items():
        print(f"--- Attempt: {k} ---", file=sys.stderr)
        print(v, file=sys.stderr)

    raise RuntimeError(
        "Could not find a Flask `app` instance or create_app() in the repository.\n"
        "Tried these module names: " + ", ".join(candidates) + "\n"
        "Make sure you expose a Flask instance named `app` (e.g. `app = Flask(__name__)`) in app.py, main.py,\n"
        "or provide a create_app() factory that returns a Flask app. See Vercel logs for import tracebacks."
    )

# Expose `app` at module top-level (WSGI/ASGI entrypoint)
app = _app

# Helpful log so you'll see where it came from in the runtime logs
print(f"[wsgi] Exposed Flask app from: {source}", file=sys.stdout)
