"""
app.py — Flask Web Server for Brute Force Simulator
====================================================
Replaces the Tkinter GUI with a browser-based interface.
Core logic (auth, simulator, wordlist, logger) is unchanged.

Routes:
  GET  /              — Main dashboard
  GET  /api/status    — Account status JSON
  POST /api/start     — Start attack, returns session id
  GET  /api/stream    — SSE stream of live attempt events
  POST /api/stop      — Stop running attack
  POST /api/reset     — Reset all accounts
  GET  /api/wordlist  — Preview smart wordlist for a username
"""

import json
import queue
import threading
import time
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request

from core.auth      import AuthSystem
from core.logger    import AttemptLogger
from core.simulator import BruteForceSimulator
from core.wordlist  import generate as generate_wordlist, preview as preview_wordlist

app      = Flask(__name__)
auth     = AuthSystem()
sim      = BruteForceSimulator(auth)
logger   = AttemptLogger()

# SSE event queue — items pushed here, streamed to browser
_event_q: queue.Queue = queue.Queue(maxsize=500)
_result_store: dict   = {}   # stores final AttackResult after done


# ── Helpers ────────────────────────────────────────────────────────────────────

def _push(event_type: str, data: dict):
    """Push an SSE event into the queue (non-blocking)."""
    try:
        _event_q.put_nowait({"type": event_type, "data": data})
    except queue.Full:
        pass


def _on_attempt(entry: dict):
    logger.log(entry)
    _push("attempt", entry)


def _on_phase(phase_num: int, description: str, total: int):
    _push("phase", {"phase": phase_num, "description": description, "total": total})


def _on_done(result):
    _result_store["last"] = result
    report = logger.write_summary(result)
    _push("done", {
        "found":         result.found_password,
        "total":         result.total_attempts,
        "blocked":       result.blocked_count,
        "time":          round(result.total_time, 2),
        "stopped":       result.was_stopped,
        "phase":         result.phase,
        "report_path":   str(report),
    })


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    accounts = list(auth.accounts.keys())
    return render_template("index.html", accounts=accounts)


@app.route("/api/status")
def api_status():
    username = request.args.get("username", "bob")
    return jsonify(auth.get_account_status(username))


@app.route("/api/wordlist")
def api_wordlist():
    username = request.args.get("username", "bob")
    return jsonify({"wordlist": preview_wordlist(username, max_lines=60)})


@app.route("/api/start", methods=["POST"])
def api_start():
    if sim.is_running():
        return jsonify({"error": "Attack already running"}), 400

    body        = request.get_json(force=True)
    username    = body.get("username", "bob")
    custom_wl   = body.get("wordlist", "").strip()
    speed       = float(body.get("speed", 0.05))
    bf_mode     = body.get("bf_mode", "lower+digits")
    bf_max_len  = int(body.get("bf_max_len", 3))
    run_bf      = body.get("run_brute_force", True)

    # Drain old events
    while not _event_q.empty():
        try: _event_q.get_nowait()
        except: pass

    auth.reset_account(username)

    wordlist = (
        [w.strip() for w in custom_wl.splitlines() if w.strip()]
        if custom_wl else
        generate_wordlist(username)
    )

    sim.start_attack(
        target_username = username,
        wordlist        = wordlist,
        on_attempt      = _on_attempt,
        on_phase        = _on_phase,
        on_done         = _on_done,
        speed_delay     = speed,
        bf_mode         = bf_mode,
        bf_max_len      = bf_max_len,
        run_brute_force = run_bf,
    )
    return jsonify({"status": "started", "username": username})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    sim.stop()
    return jsonify({"status": "stopping"})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    sim.stop()
    time.sleep(0.1)
    for u in auth.accounts:
        auth.reset_account(u)
    while not _event_q.empty():
        try: _event_q.get_nowait()
        except: pass
    return jsonify({"status": "reset"})


@app.route("/api/add_account", methods=["POST"])
def api_add_account():
    body     = request.get_json(force=True)
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(username) > 32 or len(password) > 64:
        return jsonify({"error": "Username/password too long"}), 400
    from core.auth import Account, _hash_password
    auth.accounts[username] = Account(
        username      = username,
        password_hash = _hash_password(password)
    )
    return jsonify({"status": "added", "username": username})


@app.route("/api/accounts")
def api_accounts():
    return jsonify({"accounts": list(auth.accounts.keys())})


def api_stream():
    """Server-Sent Events endpoint — browser connects once and receives live updates."""
    def generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            try:
                event = _event_q.get(timeout=30)
                payload = json.dumps({"type": event["type"], **event["data"]})
                yield f"data: {payload}\n\n"
            except queue.Empty:
                yield ": heartbeat\n\n"   # keep connection alive

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        }
    )


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
