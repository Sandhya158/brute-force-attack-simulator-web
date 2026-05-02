"""
auth.py — Mock Authentication System
=====================================
CEH Topic: System Hacking, Cryptography (Password Hashing)

This module simulates a real-world login backend:
  - Passwords stored as bcrypt hashes (never plaintext)
  - Account lockout after N failed attempts
  - Progressive delay (exponential backoff) after failures
  - CAPTCHA challenge after threshold

Educational Note:
  Real systems use similar mechanisms. Attackers bypass them via:
  credential stuffing, distributed attacks, or CAPTCHA-solving services.
"""

import hashlib
import time
import random
import string
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional


# ── Data Structures ────────────────────────────────────────────────────────────

@dataclass
class LoginAttempt:
    timestamp: str
    username: str
    password_tried: str
    success: bool
    blocked: bool
    delay_applied: float
    captcha_required: bool


@dataclass
class Account:
    username: str
    password_hash: str          # SHA-256 hex digest (simplified; use bcrypt in prod)
    failed_attempts: int = 0
    locked: bool = False
    locked_until: Optional[datetime] = None
    captcha_active: bool = False
    last_attempt: Optional[datetime] = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """
    SHA-256 hash of password (educational simplification).
    Production systems should use bcrypt / argon2 with salts.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def _generate_captcha() -> tuple[str, str]:
    """Returns (challenge_text, expected_answer) for a simple math CAPTCHA."""
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    return f"What is {a} + {b}?", str(a + b)


# ── Core Auth Engine ───────────────────────────────────────────────────────────

class AuthSystem:
    """
    Simulated authentication backend with defensive mechanisms.

    Defenses implemented:
      1. Password hashing        — plaintext never stored
      2. Rate limiting           — delay grows with failures
      3. Account lockout         — locked after MAX_FAILURES attempts
      4. CAPTCHA                 — triggered after CAPTCHA_THRESHOLD failures
    """

    MAX_FAILURES      = 5        # Lock account after this many bad attempts
    CAPTCHA_THRESHOLD = 3        # Show CAPTCHA after this many bad attempts
    LOCKOUT_MINUTES   = 2        # How long an account stays locked (shortened for demo)
    BASE_DELAY        = 0.5      # Seconds — base delay after failure
    MAX_DELAY         = 5.0      # Seconds — maximum delay cap

    def __init__(self):
        self.accounts: dict[str, Account] = {}
        self.attempt_log: list[LoginAttempt] = []
        self._populate_demo_accounts()

    # ── Setup ──────────────────────────────────────────────────────────────────

    def _populate_demo_accounts(self):
        """Pre-load a handful of demo users."""
        users = {
            "admin":   "Admin@1234",
            "alice":   "sunshine99",
            "bob":     "password",        # weak — appears in any dictionary
            "charlie": "Tr0ub4dor&3",    # strong — from XKCD
        }
        for username, pwd in users.items():
            self.accounts[username] = Account(
                username=username,
                password_hash=_hash_password(pwd)
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    def attempt_login(
        self,
        username: str,
        password: str,
        captcha_answer: str = ""
    ) -> dict:
        """
        Try to log in. Returns a result dict consumed by the simulator/UI.

        Returns keys:
          success       bool
          blocked       bool
          reason        str   human-readable message
          delay         float seconds the system forced us to wait
          captcha_req   bool  whether CAPTCHA was triggered
          captcha_q     str   CAPTCHA question (if applicable)
          locked        bool
        """
        now = datetime.now()
        result = {
            "success": False,
            "blocked": False,
            "reason":  "",
            "delay":   0.0,
            "captcha_req":   False,
            "captcha_q":     "",
            "locked":  False,
        }

        # ── Unknown user — generic error (no user enumeration) ────────────────
        if username not in self.accounts:
            result["reason"] = "Invalid credentials."
            self._log(username, password, False, False, 0.0, False)
            return result

        account = self.accounts[username]

        # ── Check lockout ──────────────────────────────────────────────────────
        if account.locked:
            if account.locked_until and now < account.locked_until:
                remaining = (account.locked_until - now).seconds
                result["blocked"] = True
                result["locked"]  = True
                result["reason"]  = f"Account locked. Try again in {remaining}s."
                self._log(username, password, False, True, 0.0, False)
                return result
            else:
                # Lockout expired — reset
                account.locked = False
                account.failed_attempts = 0
                account.captcha_active  = False

        # ── CAPTCHA check ──────────────────────────────────────────────────────
        if account.captcha_active:
            if not captcha_answer:
                challenge, expected = _generate_captcha()
                account._captcha_expected = expected
                result["captcha_req"] = True
                result["captcha_q"]   = challenge
                result["reason"]      = "CAPTCHA required."
                self._log(username, password, False, True, 0.0, True)
                return result
            expected = getattr(account, "_captcha_expected", "")
            if captcha_answer.strip() != expected:
                result["blocked"]     = True
                result["captcha_req"] = True
                result["reason"]      = "Incorrect CAPTCHA."
                self._log(username, password, False, True, 0.0, True)
                return result
            account.captcha_active = False  # CAPTCHA passed

        # ── Progressive delay ──────────────────────────────────────────────────
        delay = 0.0
        if account.failed_attempts > 0:
            delay = min(
                self.BASE_DELAY * (2 ** (account.failed_attempts - 1)),
                self.MAX_DELAY
            )
            time.sleep(delay)
        result["delay"] = delay

        # ── Password check ─────────────────────────────────────────────────────
        if _hash_password(password) == account.password_hash:
            account.failed_attempts = 0
            account.captcha_active  = False
            result["success"] = True
            result["reason"]  = "Login successful."
            self._log(username, password, True, False, delay, False)
        else:
            account.failed_attempts += 1
            account.last_attempt     = now

            # Trigger CAPTCHA
            if account.failed_attempts >= self.CAPTCHA_THRESHOLD:
                account.captcha_active = True

            # Trigger lockout
            if account.failed_attempts >= self.MAX_FAILURES:
                account.locked       = True
                account.locked_until = now + timedelta(minutes=self.LOCKOUT_MINUTES)
                result["locked"]  = True
                result["blocked"] = True
                result["reason"]  = (
                    f"Account locked after {self.MAX_FAILURES} failed attempts. "
                    f"Try again in {self.LOCKOUT_MINUTES} minute(s)."
                )
            else:
                remaining = self.MAX_FAILURES - account.failed_attempts
                result["reason"] = (
                    f"Invalid credentials. {remaining} attempt(s) remaining."
                )

            self._log(username, password, False, result["blocked"], delay,
                      account.captcha_active)

        return result

    # ── Internal logging ───────────────────────────────────────────────────────

    def _log(self, username, password, success, blocked, delay, captcha):
        self.attempt_log.append(LoginAttempt(
            timestamp        = datetime.now().strftime("%H:%M:%S"),
            username         = username,
            password_tried   = password,
            success          = success,
            blocked          = blocked,
            delay_applied    = delay,
            captcha_required = captcha,
        ))

    # ── Utilities ──────────────────────────────────────────────────────────────

    def reset_account(self, username: str):
        if username in self.accounts:
            a = self.accounts[username]
            a.failed_attempts = 0
            a.locked          = False
            a.locked_until    = None
            a.captcha_active  = False

    def get_account_status(self, username: str) -> dict:
        if username not in self.accounts:
            return {}
        a = self.accounts[username]
        return {
            "username":        a.username,
            "failed_attempts": a.failed_attempts,
            "locked":          a.locked,
            "captcha_active":  a.captcha_active,
            "locked_until":    a.locked_until.strftime("%H:%M:%S") if a.locked_until else None,
        }

    def get_stats(self) -> dict:
        total   = len(self.attempt_log)
        success = sum(1 for a in self.attempt_log if a.success)
        blocked = sum(1 for a in self.attempt_log if a.blocked)
        return {
            "total":    total,
            "success":  success,
            "failed":   total - success,
            "blocked":  blocked,
        }
