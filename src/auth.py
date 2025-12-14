import json
from pathlib import Path
from passlib.hash import bcrypt
from typing import Optional

USERS_FILE = Path(__file__).parent / "auth.json"


def _load() -> dict:
    if not USERS_FILE.exists():
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_user(username: str, password_plain: str) -> None:
    data = _load()
    if username in data:
        raise ValueError("user exists")
    hashed = bcrypt.hash(password_plain)
    data[username] = {"password": hashed}
    _save(data)


def verify_user(username: str, password_plain: str) -> bool:
    data = _load()
    entry = data.get(username)
    if not entry:
        return False
    try:
        return bcrypt.verify(password_plain, entry["password"])
    except Exception:
        return False


def users_exist() -> bool:
    return len(_load()) > 0


def list_users() -> dict:
    return _load()
