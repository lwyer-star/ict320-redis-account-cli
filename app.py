#!/usr/bin/env python3
"""
Redis Account CLI (UniSC ICT320)
- Create account
- Login
- Reset password via security question
- Bulk import from CSV
- Basic input validation and gentle throttle
"""

import csv
import getpass
import os
import re
import sys
from datetime import datetime

import bcrypt
import redis
from dotenv import load_dotenv

# ----------------------------
# Config / constants
# ----------------------------

SECURITY_QUESTIONS = [
    "What is your favourite colour?",
    "What was the name of your first pet?",
    "What city were you born in?",
]

# Throttle settings (per username/email)
THROTTLE_LIMIT = 5          # attempts
THROTTLE_TTL_SECONDS = 300  # 5 minutes

# Toggle to show hashed values when creating/importing (for demo logs)
VISIBLE_PASSWORDS = os.getenv("VISIBLE_PASSWORDS", "0") == "1"

# ----------------------------
# Helpers (validation, keys, logging)
# ----------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def looks_like_email(s: str) -> bool:
    return bool(EMAIL_RE.match((s or "").strip()))


def strong_enough(pw: str) -> tuple[bool, str]:
    if len(pw) < 8:
        return False, "Use at least 8 characters."
    # (Optionally add: upper/lower/digit/special checks)
    return True, ""


def key_user(login: str) -> str:
    return f"user:{login}"


def key_pw(login: str) -> str:
    return f"pass:{login}"


def key_sec_q(login: str) -> str:
    return f"secq:{login}"


def key_sec_a(login: str) -> str:
    return f"seca:{login}"


def key_fail(login: str) -> str:
    return f"fail:{login}"


def log_event(kind: str, login: str, outcome: str, extra: str = "") -> None:
    """
    Simple console + file logger with masked login.
    """
    masked = mask_login(login)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | {kind:<12} | {masked:<20} | {outcome}"
    if extra:
        line += f" | {extra}"
    print(line)
    try:
        with open("auth.log", "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        # Don't crash on logging issues
        pass


def mask_login(login: str) -> str:
    s = (login or "").strip()
    if len(s) <= 2:
        return "***"
    return s[0] + "***" + s[-1]


def prompt_nonempty(prompt: str) -> str:
    while True:
        s = input(prompt).strip()
        if s:
            return s
        print("Please enter a value.")


# ----------------------------
# Redis connection / throttle
# ----------------------------

def connect() -> redis.Redis:
    """
    Load .env and connect to Redis; exit with a clear error if misconfigured.
    """
    load_dotenv()
    url = os.getenv("REDIS_URL")
    if not url:
        print("ERROR: REDIS_URL not set. Copy .env.example to .env and fill it in.")
        sys.exit(1)
    try:
        r = redis.from_url(url, decode_responses=True)
        r.ping()
        print("Connected to Redis ✅")
        return r
    except Exception as e:
        print(f"ERROR: cannot connect to Redis: {e}")
        sys.exit(1)


def allowed_to_attempt(r: redis.Redis, login: str) -> bool:
    tries = int(r.get(key_fail(login)) or 0)
    return tries < THROTTLE_LIMIT


def bump_fail(r: redis.Redis, login: str) -> None:
    k = key_fail(login)
    tries = r.incr(k)
    if tries == 1:
        r.expire(k, THROTTLE_TTL_SECONDS)


def clear_fail(r: redis.Redis, login: str) -> None:
    r.delete(key_fail(login))


# ----------------------------
# Core flows
# ----------------------------

def list_security_questions() -> None:
    print("\nSecurity questions:")
    for idx, q in enumerate(SECURITY_QUESTIONS, start=1):
        print(f"  [{idx}] {q}")
    print()


def create_account(r: redis.Redis) -> None:
    print("\n== Create account ==")
    login = prompt_nonempty("Login (email or username): ").lower()

    # Optional: if it contains '@', validate email form
    if "@" in login and not looks_like_email(login):
        print("That doesn’t look like a valid email.")
        return

    if r.exists(key_user(login)):
        print("Account already exists.")
        return

    first = prompt_nonempty("First name: ")

    pw = getpass.getpass("Password: ")
    ok, why = strong_enough(pw)
    if not ok:
        print(why)
        return
    pw_hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    # Choose security question
    list_security_questions()
    try:
        q_idx = int(prompt_nonempty("Choose a security question number: "))
        if not 1 <= q_idx <= len(SECURITY_QUESTIONS):
            raise ValueError
    except ValueError:
        print("Invalid choice.")
        return
    sec_q = SECURITY_QUESTIONS[q_idx - 1]
    sec_a = getpass.getpass("Answer: ")
    if not sec_a.strip():
        print("Security answer required.")
        return
    sec_a_hashed = bcrypt.hashpw(sec_a.encode(), bcrypt.gensalt()).decode()

    # Persist
    r.hset(key_user(login), mapping={"first": first})
    r.set(key_pw(login), pw_hashed)
    r.set(key_sec_q(login), sec_q)
    r.set(key_sec_a(login), sec_a_hashed)

    extra = ""
    if VISIBLE_PASSWORDS:
        extra = f"pw={pw_hashed[:25]}..., seca={sec_a_hashed[:25]}..."
    log_event("create", login, "ok", extra)
    print("Account created.\n")


def login_flow(r: redis.Redis) -> None:
    print("\n== Login ==")
    login = prompt_nonempty("Login (email or username): ").lower()

    if not allowed_to_attempt(r, login):
        print("Too many attempts. Try again in a few minutes.")
        log_event("login", login, "throttled")
        return

    stored_hash = r.get(key_pw(login))
    if not stored_hash:
        print("No such account.")
        log_event("login", login, "no_account")
        return

    pw = getpass.getpass("Password: ")
    if bcrypt.checkpw(pw.encode(), stored_hash.encode()):
        first = r.hget(key_user(login), "first") or "there"
        clear_fail(r, login)
        log_event("login", login, "ok")
        print(f"Welcome, {first}!\n")
    else:
        bump_fail(r, login)
        log_event("login", login, "wrong_pw")
        print("Incorrect password.\n")


def reset_password_flow(r: redis.Redis) -> None:
    print("\n== Reset password ==")
    login = prompt_nonempty("Login (email or username): ").lower()
    if not r.exists(key_user(login)):
        print("No such account.")
        log_event("reset", login, "no_account")
        return

    q = r.get(key_sec_q(login)) or "Security question not set."
    print(f"Security question: {q}")
    ans = getpass.getpass("Answer: ")
    stored_a = r.get(key_sec_a(login))
    if not stored_a:
        print("No security answer on file.")
        log_event("reset", login, "no_sec_answer")
        return

    if not bcrypt.checkpw(ans.encode(), stored_a.encode()):
        log_event("reset", login, "wrong_answer")
        print("Incorrect answer.")
        return

    new_pw = getpass.getpass("New password: ")
    ok, why = strong_enough(new_pw)
    if not ok:
        print(why)
        return
    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    r.set(key_pw(login), new_hash)
    log_event("reset", login, "ok")
    print("Password updated.\n")


def load_from_csv(r: redis.Redis) -> None:
    """
    CSV must contain header: username,password,firstname
    For demo, sets default security question #1 and answer 'blue'.
    """
    print("\n== Bulk import from CSV ==")
    path = prompt_nonempty("CSV path: ")
    if not os.path.exists(path):
        print("File not found.")
        log_event("bulk_import", "csv", "missing_file", path)
        return

    imported = 0
    skipped = 0
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)

        expected = {"username", "password", "firstname"}
        actual = set(map(str.lower, reader.fieldnames or []))
        if expected & actual != expected:
            print(f"CSV must contain columns: {', '.join(sorted(expected))}")
            log_event("bulk_import", "csv", "bad_header", ",".join(reader.fieldnames or []))
            return

        for row in reader:
            login = (row.get("username") or "").strip().lower()
            pw = (row.get("password") or "").strip()
            first = (row.get("firstname") or "").strip()

            if not login or not pw or not first:
                skipped += 1
                continue

            # If the CSV uses emails, validate (optional)
            if "@" in login and not looks_like_email(login):
                skipped += 1
                continue

            if r.exists(key_user(login)):
                skipped += 1
                continue

            ok, _ = strong_enough(pw)
            if not ok:
                skipped += 1
                continue

            pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
            sec_q = SECURITY_QUESTIONS[0]  # default for demo
            sec_a_hash = bcrypt.hashpw(b"blue", bcrypt.gensalt()).decode()

            r.hset(key_user(login), mapping={"first": first})
            r.set(key_pw(login), pw_hash)
            r.set(key_sec_q(login), sec_q)
            r.set(key_sec_a(login), sec_a_hash)

            imported += 1
            extra = f"pw={pw_hash[:25]}..." if VISIBLE_PASSWORDS else ""
            log_event("import", login, "ok", extra)

    print(f"Import complete. Imported: {imported}, Skipped: {skipped}\n")


# ----------------------------
# UI loop
# ----------------------------

def main_menu(r: redis.Redis) -> None:
    while True:
        print(
            "\n[1] Create account"
            "  [2] Login"
            "  [3] Reset password"
            "  [4] List security questions"
            "  [5] Bulk import from CSV"
            "  [6] Exit"
        )
        choice = input("> ").strip()
        if choice == "1":
            create_account(r)
        elif choice == "2":
            login_flow(r)
        elif choice == "3":
            reset_password_flow(r)
        elif choice == "4":
            list_security_questions()
        elif choice == "5":
            load_from_csv(r)
        elif choice == "6":
            print("Goodbye!")
            break
        else:
            print("Invalid option.\n")


def main() -> None:
    r = connect()
    try:
        main_menu(r)
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
