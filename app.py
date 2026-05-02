"""
app.py — Flask Web Server for Brute Force Simulator
====================================================
Uses polling (/api/poll) instead of SSE for broad compatibility
with Render, gunicorn, nginx, and all browsers.
"""

import json
import time
import threading
from collections import deque

from flask import Flask, jsonify, render_template, request

from core.auth      import AuthSystem
from core.logger    import AttemptLogger
from core.simulator import BruteForceSimulator
from core.wordlist  import generate as generate_wordlist, preview as preview_wordlist

app    = Flask(__name__)
auth   = AuthSystem()
sim    = BruteForceSimulator(auth)
logger = AttemptLogger()

_events: deque  = deque(maxlen=1000)
_event_lock     = threading.Lock()
_attack_running = False


def _push(event_type: str, data: dict):
    with _event_lock:
        _events.append({"type": event_type, **data})

def _on_attempt(entry: dict):
    logger.log(entry)
    _push("attempt", entry)

def _on_phase(phase_num: int, description: str, total: int):
    _push("phase", {"phase": phase_num, "description": description, "total": total})

def _on_done(result):
    global _attack_running
    _attack_running = False
    logger.write_summary(result)
    _push("done", {
        "found":   result.found_password,
        "total":   result.total_attempts,
        "blocked": result.blocked_count,
        "time":    round(result.total_time, 2),
        "stopped": result.was_stopped,
        "phase":   getattr(result, "phase", 1),
    })

@app.route("/")
def index():
    return render_template("index.html", accounts=list(auth.accounts.keys()))

@app.route("/api/status")
def api_status():
    return jsonify(auth.get_account_status(request.args.get("username", "bob")))

@app.route("/api/wordlist")
def api_wordlist():
    return jsonify({"wordlist": preview_wordlist(request.args.get("username", "bob"), max_lines=60)})

@app.route("/api/accounts")
def api_accounts():
    return jsonify({"accounts": list(auth.accounts.keys())})

@app.route("/api/add_account", methods=["POST"])
def api_add_account():
    body = request.get_json(force=True)
    u = body.get("username", "").strip()
    p = body.get("password", "").strip()
    if not u or not p:
        return jsonify({"error": "Username and password required"}), 400
    from core.auth import Account, _hash_password
    auth.accounts[u] = Account(username=u, password_hash=_hash_password(p))
    return jsonify({"status": "added", "username": u})

@app.route("/api/start", methods=["POST"])
def api_start():
    global _attack_running
    if sim.is_running():
        return jsonify({"error": "Attack already running"}), 400
    body = request.get_json(force=True)
    username   = body.get("username", "bob")
    custom_wl  = body.get("wordlist", "").strip()
    speed      = float(body.get("speed", 0.05))
    bf_mode    = body.get("bf_mode", "lower+digits")
    bf_max_len = int(body.get("bf_max_len", 3))
    run_bf     = body.get("run_brute_force", True)
    with _event_lock:
        _events.clear()
    auth.reset_account(username)
    _attack_running = True
    wordlist = (
        [w.strip() for w in custom_wl.splitlines() if w.strip()]
        if custom_wl else generate_wordlist(username)
    )
    sim.start_attack(
        target_username=username, wordlist=wordlist,
        on_attempt=_on_attempt, on_phase=_on_phase, on_done=_on_done,
        speed_delay=speed, bf_mode=bf_mode, bf_max_len=bf_max_len,
        run_brute_force=run_bf,
    )
    return jsonify({"status": "started", "username": username})

@app.route("/api/poll")
def api_poll():
    try:
        cursor = int(request.args.get("cursor", 0))
    except ValueError:
        cursor = 0
    with _event_lock:
        all_events = list(_events)
    new_events = all_events[cursor:]
    return jsonify({
        "events":  new_events,
        "cursor":  cursor + len(new_events),
        "running": _attack_running or sim.is_running(),
    })

@app.route("/api/stop", methods=["POST"])
def api_stop():
    global _attack_running
    sim.stop()
    _attack_running = False
    return jsonify({"status": "stopping"})

@app.route("/api/reset", methods=["POST"])
def api_reset():
    global _attack_running
    sim.stop()
    _attack_running = False
    time.sleep(0.1)
    for u in auth.accounts:
        auth.reset_account(u)
    with _event_lock:
        _events.clear()
    return jsonify({"status": "reset"})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
