
import re
import time
import threading
from typing import Callable, Optional

from core.auth import AuthSystem
from core.wordlist import (
    generate                    as generate_wordlist,
    generate_case_mutation_list as generate_case_list,
    brute_force_generator,
    brute_force_count,
    charset_for_mode,
    COMMON_PASSWORDS,
    CHARSET_FULL,
    MAX_BF_LENGTH,
)


# ── Attack result container ────────────────────────────────────────────────────

class AttackResult:
    """Aggregates results from one complete attack run (both phases)."""

    def __init__(self):
        self.attempts:        list[dict] = []
        self.found_password:  Optional[str] = None
        self.total_time:      float = 0.0
        self.was_stopped:     bool  = False
        self.phase:           int   = 1      # which phase found the password

    @property
    def total_attempts(self): return len(self.attempts)

    @property
    def blocked_count(self):  return sum(1 for a in self.attempts if a["blocked"])

    @property
    def success_count(self):  return sum(1 for a in self.attempts if a["success"])


# ── Main simulator ─────────────────────────────────────────────────────────────

class BruteForceSimulator:
    """
    Runs Phase 1 (smart dictionary) then Phase 2 (brute force) against AuthSystem.

    Usage:
        sim = BruteForceSimulator(auth)
        sim.start_attack(
            "sonu",
            on_attempt   = my_callback,   # called after every attempt
            on_phase     = phase_callback, # called when switching phases
            on_done      = done_callback,  # called when finished
            bf_mode      = "lower+digits", # charset mode for phase 2
            bf_max_len   = 4,              # max length for phase 2
        )
    """

    def __init__(self, auth: AuthSystem):
        self.auth    = auth
        self._stop   = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── Public ─────────────────────────────────────────────────────────────────

    def start_attack(
        self,
        target_username:  str,
        wordlist:         Optional[list[str]]          = None,
        on_attempt:       Optional[Callable[[dict], None]]  = None,
        on_phase:         Optional[Callable[[int, str, int], None]] = None,
        on_done:          Optional[Callable[[AttackResult], None]]  = None,
        speed_delay:      float  = 0.02,
        bf_mode:          str    = "lower+digits",
        bf_max_len:       int    = MAX_BF_LENGTH,
        run_brute_force:  bool   = True,
    ):
        """
        Launch the two-phase attack in a background thread.

        Args:
            target_username : Username to attack.
            wordlist        : Override Phase 1 list (auto-generated if None).
            on_attempt      : Callback(entry_dict) after each attempt.
            on_phase        : Callback(phase_num, description, total_count).
            on_done         : Callback(AttackResult) when finished.
            speed_delay     : Seconds between attempts (UI pacing).
            bf_mode         : Charset for Phase 2 — 'digits', 'lower',
                              'lower+digits', or 'full'.
            bf_max_len      : Max password length to brute force (1–4).
            run_brute_force : Set False to skip Phase 2 (dict only).
        """
        self._stop.clear()
        wordlist = wordlist or generate_wordlist(target_username)

        self._thread = threading.Thread(
            target=self._run,
            args=(target_username, wordlist, on_attempt, on_phase,
                  on_done, speed_delay, bf_mode, bf_max_len, run_brute_force),
            daemon=True,
        )
        self._thread.start()

    # Keep old method name as alias so existing callers don't break
    def start_dictionary_attack(self, target_username, wordlist=None,
                                 on_attempt=None, on_done=None, speed_delay=0.05):
        self.start_attack(target_username, wordlist=wordlist,
                          on_attempt=on_attempt, on_done=on_done,
                          speed_delay=speed_delay, run_brute_force=False)

    def stop(self):
        self._stop.set()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _solve_captcha(question: str) -> str:
        """
        Auto-solve the simple math CAPTCHA.

        Educational Note:
          Real attackers use CAPTCHA-solving services (2captcha, Anti-Captcha)
          or ML image classifiers. Simple arithmetic CAPTCHAs are bypassed
          trivially — they only stop naive scripts, not motivated attackers.
        """
        nums = re.findall(r"\d+", question)
        if len(nums) == 2:
            return str(int(nums[0]) + int(nums[1]))
        return ""

    def _attempt(self, username: str, password: str) -> dict:
        """Try one password, auto-solving CAPTCHA if triggered."""
        res = self.auth.attempt_login(username, password)
        if res.get("captcha_req") and res.get("captcha_q"):
            ans = self._solve_captcha(res["captcha_q"])
            if ans:
                res = self.auth.attempt_login(username, password, captcha_answer=ans)
        return res

    def _run(self, username, wordlist, on_attempt, on_phase,
             on_done, speed_delay, bf_mode, bf_max_len, run_brute_force):

        result  = AttackResult()
        t_start = time.time()
        auth    = self.auth
        tried:  set[str] = set()   # track phase-1 attempts for phase-2 skip

        auth.reset_account(username)

        # ══════════════════════════════════════════════════════════════════════
        #  PHASE 1 — Smart Dictionary Attack
        # ══════════════════════════════════════════════════════════════════════
        phase1_count = len(wordlist)
        if on_phase:
            on_phase(1, "Smart Dictionary Attack", phase1_count)

        for password in wordlist:
            if self._stop.is_set():
                result.was_stopped = True
                break

            tried.add(password)
            res = self._attempt(username, password)
            entry = self._make_entry(username, password, res, phase=1)
            result.attempts.append(entry)

            if on_attempt:
                on_attempt(entry)

            if res["success"]:
                result.found_password = password
                result.phase          = 1
                result.total_time     = time.time() - t_start
                if on_done:
                    on_done(result)
                return

            if res["locked"]:
                time.sleep(0.2)
                auth.reset_account(username)

            time.sleep(speed_delay)

        if result.was_stopped:
            result.total_time = time.time() - t_start
            if on_done:
                on_done(result)
            return

        # ══════════════════════════════════════════════════════════════════════
        #  PHASE 1.5 — Case-Mutation Attack  (CEH Module 6: System Hacking)
        # ══════════════════════════════════════════════════════════════════════
        # Many users use their username with mixed capitalisation as a password.
        # This phase exhausts every upper/lower permutation of the username
        # and common username+suffix combos — identical to Hashcat's 'toggle'
        # rule. It catches passwords like "JoHn", "jOHN", "aDmIn", "AlIcE1" etc.
        #
        # Without this phase, a case-varied 4-char password would require
        # traversing millions of brute-force candidates before being found.
        # With it, we check at most 2^len(username) × seed_count variants first.
        # ──────────────────────────────────────────────────────────────────────
        case_list = [p for p in generate_case_list(username) if p not in tried]
        case_total = len(case_list)

        if case_total > 0:
            if on_phase:
                on_phase(
                    "1.5",
                    f"Case-Mutation Attack  |  toggle-case permutations  |  ~{case_total} combos",
                    case_total,
                )

            auth.reset_account(username)

            for password in case_list:
                if self._stop.is_set():
                    result.was_stopped = True
                    break

                tried.add(password)
                res   = self._attempt(username, password)
                entry = self._make_entry(username, password, res, phase="1.5")
                result.attempts.append(entry)

                if on_attempt:
                    on_attempt(entry)

                if res["success"]:
                    result.found_password = password
                    result.phase          = "1.5"
                    result.total_time     = time.time() - t_start
                    if on_done:
                        on_done(result)
                    return

                if res["locked"]:
                    time.sleep(0.2)
                    auth.reset_account(username)

                time.sleep(speed_delay)

        if result.was_stopped or not run_brute_force:
            result.total_time = time.time() - t_start
            if on_done:
                on_done(result)
            return

        # ══════════════════════════════════════════════════════════════════════
        charset     = charset_for_mode(bf_mode)
        bf_total    = brute_force_count(bf_max_len, charset)
        description = (
            f"Brute Force  |  charset={bf_mode}  "
            f"|  max_len={bf_max_len}  |  ~{bf_total:,} combos"
        )

        if on_phase:
            on_phase(2, description, bf_total)

        auth.reset_account(username)

        for password in brute_force_generator(
            max_length=bf_max_len,
            charset=charset,
            skip_set=tried,          # skip anything already tried in phase 1
        ):
            if self._stop.is_set():
                result.was_stopped = True
                break

            res   = self._attempt(username, password)
            entry = self._make_entry(username, password, res, phase=2)
            result.attempts.append(entry)

            if on_attempt:
                on_attempt(entry)

            if res["success"]:
                result.found_password = password
                result.phase          = 2
                break

            if res["locked"]:
                time.sleep(0.2)
                auth.reset_account(username)

            time.sleep(speed_delay)

        result.total_time = time.time() - t_start
        if on_done:
            on_done(result)

    @staticmethod
    def _make_entry(username: str, password: str, res: dict, phase: int) -> dict:
        return {
            "username": username,
            "password": password,
            "success":  res["success"],
            "blocked":  res["blocked"],
            "locked":   res["locked"],
            "delay":    res["delay"],
            "captcha":  res["captcha_req"],
            "reason":   res["reason"],
            "phase":    phase,
        }
