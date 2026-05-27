# -*- coding: utf-8 -*-
"""
Web admin authentication module.

Single toggle (ADMIN_AUTH_ENABLED) + file-based credentials.
First login sets initial password; supports web change-password and CLI reset.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import logging
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from dotenv import dotenv_values

logger = logging.getLogger(__name__)

COOKIE_NAME = "dsa_session"
PBKDF2_ITERATIONS = 100_000
RATE_LIMIT_WINDOW_SEC = 300
RATE_LIMIT_MAX_FAILURES = 5
SESSION_MAX_AGE_HOURS_DEFAULT = 24
MIN_PASSWORD_LEN = 6

# Lazy-loaded state
_auth_enabled: Optional[bool] = None
_session_secret: Optional[bytes] = None
_password_hash_salt: Optional[bytes] = None
_password_hash_stored: Optional[bytes] = None
_rate_limit: dict[str, Tuple[int, float]] = {}
_rate_limit_lock = None


def _get_lock():
    """Lazy init threading lock for rate limit dict."""
    global _rate_limit_lock
    if _rate_limit_lock is None:
        import threading
        _rate_limit_lock = threading.Lock()
    return _rate_limit_lock


def _ensure_env_loaded() -> None:
    """Ensure .env is loaded before reading config."""
    from src.config import setup_env
    setup_env()


def _get_data_dir() -> Path:
    """Return DATA_DIR as parent of DATABASE_PATH."""
    db_path = os.getenv("DATABASE_PATH", "./data/stock_analysis.db")
    return Path(db_path).resolve().parent


def _get_credential_path() -> Path:
    """Path to stored password hash file."""
    return _get_data_dir() / ".admin_password_hash"


def _get_user_db_session():
    """Get a database session for user operations. Returns None if DB not available."""
    try:
        from src.storage import DatabaseManager
        return DatabaseManager.get_instance().get_session()
    except Exception:
        return None


def _has_users_table() -> bool:
    """Check if the users table exists and has at least one row."""
    session = _get_user_db_session()
    if session is None:
        return False
    try:
        from src.storage import User
        count = session.query(User.id).count()
        return count > 0
    except Exception:
        return False
    finally:
        session.close()


def _is_multi_user_mode() -> bool:
    """Return True when users table exists with at least one user."""
    return _has_users_table()


def create_user(
    username: str,
    password: str,
    display_name: str | None = None,
    is_admin: bool = False,
) -> tuple[object | None, str | None]:
    """Create a new user. Returns (user, error_message)."""
    from src.storage import User

    username = (username or "").strip()
    if not username:
        return None, "用户名不能为空"
    if len(username) < 2:
        return None, "用户名至少2个字符"
    if len(password) < MIN_PASSWORD_LEN:
        return None, f"密码至少 {MIN_PASSWORD_LEN} 位"

    session = _get_user_db_session()
    if session is None:
        return None, "数据库不可用"

    try:
        import base64

        existing = session.query(User).filter(User.username == username).first()
        if existing:
            return None, "用户名已存在"

        salt = secrets.token_bytes(32)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        salt_b64 = base64.standard_b64encode(salt).decode("ascii")
        hash_b64 = base64.standard_b64encode(derived).decode("ascii")

        user = User(
            username=username,
            password_hash=f"{salt_b64}:{hash_b64}",
            display_name=display_name or username,
            is_admin=is_admin,
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user, None
    except Exception as e:
        session.rollback()
        logger.error("Failed to create user: %s", e)
        return None, "创建用户失败"
    finally:
        session.close()


def authenticate_user(username: str, password: str):
    """Verify username and password. Returns User on success, None on failure."""
    from src.storage import User

    username = (username or "").strip()
    if not username or not password:
        return None

    session = _get_user_db_session()
    if session is None:
        return None

    try:
        user = session.query(User).filter(User.username == username).first()
        if user is None or not user.is_active:
            return None

        parsed = _parse_password_hash(user.password_hash)
        if parsed is None:
            return None
        salt, stored_hash = parsed
        if _verify_password_hash(password, salt, stored_hash):
            return user
        return None
    except Exception as e:
        logger.error("authenticate_user failed: %s", e)
        return None
    finally:
        session.close()


def get_user_by_id(user_id: int):
    """Get user by ID. Returns User or None."""
    from src.storage import User

    session = _get_user_db_session()
    if session is None:
        return None
    try:
        return session.query(User).filter(User.id == user_id).first()
    except Exception:
        return None
    finally:
        session.close()


def get_user_by_username(username: str):
    """Get user by username. Returns User or None."""
    from src.storage import User

    session = _get_user_db_session()
    if session is None:
        return None
    try:
        return session.query(User).filter(User.username == username).first()
    except Exception:
        return None
    finally:
        session.close()


def list_users():
    """List all active users."""
    from src.storage import User

    session = _get_user_db_session()
    if session is None:
        return []
    try:
        return session.query(User).filter(User.is_active == True).order_by(User.id).all()
    except Exception:
        return []
    finally:
        session.close()


def update_user_password(user_id: int, current_password: str, new_password: str) -> str | None:
    """Change password for a specific user. Returns None on success, error message on failure."""
    import base64

    from src.storage import User

    if len(new_password) < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"

    session = _get_user_db_session()
    if session is None:
        return "数据库不可用"

    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user is None:
            return "用户不存在"

        parsed = _parse_password_hash(user.password_hash)
        if parsed is None:
            return "密码数据异常"

        salt, stored_hash = parsed
        if not _verify_password_hash(current_password, salt, stored_hash):
            return "当前密码错误"

        new_salt = secrets.token_bytes(32)
        new_derived = hashlib.pbkdf2_hmac(
            "sha256",
            new_password.encode("utf-8"),
            salt=new_salt,
            iterations=PBKDF2_ITERATIONS,
        )
        salt_b64 = base64.standard_b64encode(new_salt).decode("ascii")
        hash_b64 = base64.standard_b64encode(new_derived).decode("ascii")
        user.password_hash = f"{salt_b64}:{hash_b64}"
        session.commit()
        return None
    except Exception as e:
        session.rollback()
        logger.error("update_user_password failed: %s", e)
        return "修改密码失败"
    finally:
        session.close()


def deactivate_user(user_id: int) -> bool:
    """Deactivate a user. Returns True on success."""
    from src.storage import User

    session = _get_user_db_session()
    if session is None:
        return False
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user is None:
            return False
        user.is_active = False
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        logger.error("deactivate_user failed: %s", e)
        return False
    finally:
        session.close()


def _is_auth_enabled_from_env() -> bool:
    """Read ADMIN_AUTH_ENABLED from .env file."""
    _ensure_env_loaded()
    env_file = os.getenv("ENV_FILE")
    env_path = Path(env_file) if env_file else Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return False
    values = dotenv_values(env_path)
    val = (values.get("ADMIN_AUTH_ENABLED") or "").strip().lower()
    return val in ("true", "1", "yes")


def rotate_session_secret() -> bool:
    """Rotate the session signing secret to invalidate all active sessions."""
    global _session_secret
    data_dir = _get_data_dir()
    secret_path = data_dir / ".session_secret"
    data_dir.mkdir(parents=True, exist_ok=True)
    new_secret = secrets.token_bytes(32)
    try:
        tmp_path = secret_path.with_suffix(".tmp")
        tmp_path.write_bytes(new_secret)
        tmp_path.chmod(0o600)
        tmp_path.replace(secret_path)
        _session_secret = new_secret
        logger.info("Session secret rotated successfully")
        return True
    except OSError as e:
        logger.error("Failed to rotate .session_secret: %s", e)
        return False


def _load_session_secret() -> Optional[bytes]:
    """Load or create session secret."""
    global _session_secret
    if _session_secret is not None:
        return _session_secret

    data_dir = _get_data_dir()
    secret_path = data_dir / ".session_secret"

    try:
        if secret_path.exists():
            _session_secret = secret_path.read_bytes()
            if len(_session_secret) != 32:
                logger.warning("Invalid .session_secret length, regenerating")
                _session_secret = None
                if rotate_session_secret():
                    return _session_secret
                return None
            return _session_secret

        data_dir.mkdir(parents=True, exist_ok=True)
        new_secret = secrets.token_bytes(32)
        try:
            with open(secret_path, "xb") as f:
                f.write(new_secret)
            secret_path.chmod(0o600)
        except FileExistsError:
            _session_secret = secret_path.read_bytes()
        else:
            _session_secret = new_secret
        return _session_secret
    except OSError as e:
        logger.error("Failed to create or read .session_secret: %s", e)
        return None


def _parse_password_hash(value: str) -> Optional[Tuple[bytes, bytes]]:
    """Parse salt_b64:hash_b64. Returns (salt, hash) or None."""
    if not value or ":" not in value:
        return None
    parts = value.strip().split(":", 1)
    if len(parts) != 2:
        return None
    try:
        salt_b64, hash_b64 = parts[0].strip(), parts[1].strip()
        salt = base64.standard_b64decode(salt_b64)
        stored_hash = base64.standard_b64decode(hash_b64)
        if salt and stored_hash:
            return (salt, stored_hash)
    except (ValueError, TypeError):
        pass
    return None


def _verify_password_hash(submitted: str, salt: bytes, stored_hash: bytes) -> bool:
    """Verify submitted password against stored pbkdf2 hash."""
    computed = hashlib.pbkdf2_hmac(
        "sha256",
        submitted.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(computed, stored_hash)


def _load_credential_from_file() -> bool:
    """Load credential from file into module globals. Returns True if loaded."""
    global _password_hash_salt, _password_hash_stored

    path = _get_credential_path()
    if not path.exists():
        _password_hash_salt = None
        _password_hash_stored = None
        return False

    try:
        raw = path.read_text().strip()
        parsed = _parse_password_hash(raw)
        if parsed is None:
            logger.warning("Invalid .admin_password_hash format, ignoring")
            return False
        _password_hash_salt, _password_hash_stored = parsed
        return True
    except OSError as e:
        logger.error("Failed to read credential file: %s", e)
        return False


def refresh_auth_state() -> None:
    """Reload auth-related state from disk and env."""
    global _auth_enabled, _session_secret
    _auth_enabled = None
    _session_secret = None
    _load_credential_from_file()


def is_auth_enabled() -> bool:
    """Return whether admin authentication is enabled (ADMIN_AUTH_ENABLED=true)."""
    global _auth_enabled
    if _auth_enabled is not None:
        return _auth_enabled
    _auth_enabled = _is_auth_enabled_from_env()
    return _auth_enabled


def has_stored_password() -> bool:
    """Return whether a valid stored password hash exists on disk."""
    return _load_credential_from_file()


def verify_stored_password(password: str) -> bool:
    """Verify password against stored credential even when auth is disabled."""
    if not has_stored_password():
        return False
    return _verify_password_hash(password, _password_hash_salt, _password_hash_stored)


def is_password_set() -> bool:
    """Return whether at least one user exists (multi-user) or password file exists (legacy)."""
    if not is_auth_enabled():
        return False
    if _is_multi_user_mode():
        return True
    return has_stored_password()


def is_password_changeable() -> bool:
    """Return whether password can be changed via web/CLI (always True when auth enabled)."""
    return is_auth_enabled()


def _get_session_secret() -> Optional[bytes]:
    """Return session signing secret."""
    if not is_auth_enabled():
        return None
    return _load_session_secret()


def _validate_password(pwd: str) -> Optional[str]:
    """Return error message if invalid, None if valid."""
    if not pwd or not pwd.strip():
        return "密码不能为空"
    if len(pwd) < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"
    return None


def set_initial_password(password: str) -> Optional[str]:
    """
    Set initial password (first-time setup). Returns error message or None on success.
    Atomic write with 0o600 permissions.
    """
    err = _validate_password(password)
    if err:
        return err

    data_dir = _get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    cred_path = _get_credential_path()

    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    salt_b64 = base64.standard_b64encode(salt).decode("ascii")
    hash_b64 = base64.standard_b64encode(derived).decode("ascii")
    content = f"{salt_b64}:{hash_b64}"

    try:
        tmp_path = cred_path.with_suffix(".tmp")
        tmp_path.write_text(content)
        tmp_path.chmod(0o600)
        tmp_path.replace(cred_path)
        _load_credential_from_file()
        return None
    except OSError as e:
        logger.error("Failed to write credential file: %s", e)
        return "密码保存失败"


def verify_password(password: str, username: str | None = None) -> bool:
    """Verify password. When username is given, authenticates against user DB. Otherwise tries legacy admin check."""
    if not is_auth_enabled():
        return True
    if username:
        return authenticate_user(username, password) is not None
    if _is_multi_user_mode():
        # In multi-user mode, legacy verify_password without username is only for the auth toggle check
        # which should use session verification instead
        return False
    return verify_stored_password(password)


def change_password(current: str, new: str, user_id: int | None = None) -> Optional[str]:
    """
    Change password. In multi-user mode, user_id is required.
    Returns error message or None on success.
    """
    if not is_auth_enabled():
        return "认证功能未启用"

    if user_id is not None:
        return update_user_password(user_id, current, new)

    # Legacy single-admin flow
    if not is_password_set():
        return "尚未设置密码"

    if not current or not current.strip():
        return "请输入当前密码"
    if not _verify_password_hash(current, _password_hash_salt, _password_hash_stored):
        return "当前密码错误"

    err = _validate_password(new)
    if err:
        return err

    cred_path = _get_credential_path()
    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        new.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    salt_b64 = base64.standard_b64encode(salt).decode("ascii")
    hash_b64 = base64.standard_b64encode(derived).decode("ascii")
    content = f"{salt_b64}:{hash_b64}"

    try:
        tmp_path = cred_path.with_suffix(".tmp")
        tmp_path.write_text(content)
        tmp_path.chmod(0o600)
        tmp_path.replace(cred_path)
        _load_credential_from_file()
        return None
    except OSError as e:
        logger.error("Failed to write credential file: %s", e)
        return "密码保存失败"


def create_session(user_id: int | None = None) -> str:
    """Create a signed session payload. Format: nonce.ts.signature or nonce.user_id.ts.signature."""
    secret = _get_session_secret()
    if not secret:
        return ""
    nonce = secrets.token_urlsafe(32)
    ts = str(int(time.time()))
    uid_str = str(user_id) if user_id is not None else ""
    payload = f"{nonce}.{uid_str}.{ts}"
    sig = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session(value: str):
    """Verify session cookie and check expiry. Returns user_id (int) or None."""
    secret = _get_session_secret()
    if not secret or not value:
        return None
    parts = value.split(".")
    if len(parts) not in (3, 4):
        return None
    if len(parts) == 3:
        nonce, ts_str, sig = parts[0], parts[1], parts[2]
        uid_str = ""
    else:
        nonce, uid_str, ts_str, sig = parts[0], parts[1], parts[2], parts[3]
    payload = f"{nonce}.{uid_str}.{ts_str}"
    expected = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        ts = int(ts_str)
    except ValueError:
        return None
    try:
        max_age_hours = int(os.getenv("ADMIN_SESSION_MAX_AGE_HOURS", str(SESSION_MAX_AGE_HOURS_DEFAULT)))
    except ValueError:
        max_age_hours = SESSION_MAX_AGE_HOURS_DEFAULT
    if time.time() - ts > max_age_hours * 3600:
        return None
    if uid_str:
        try:
            return int(uid_str)
        except ValueError:
            return None
    return None


def get_client_ip(request) -> str:
    """Get client IP, respecting TRUST_X_FORWARDED_FOR.

    When behind a single trusted reverse proxy, the proxy appends the real
    client IP as the rightmost entry in X-Forwarded-For.  We use [-1] instead
    of [0] so that an attacker cannot spoof an arbitrary leftmost value to
    rotate rate-limit buckets and bypass brute-force protection.
    """
    if os.getenv("TRUST_X_FORWARDED_FOR", "false").lower() == "true":
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    if request.client:
        return request.client.host or "127.0.0.1"
    return "127.0.0.1"


def check_rate_limit(ip: str) -> bool:
    """Return True if under limit, False if rate limited."""
    lock = _get_lock()
    now = time.time()
    with lock:
        expired_keys = [k for k, (_, ts) in _rate_limit.items() if now - ts > RATE_LIMIT_WINDOW_SEC]
        for k in expired_keys:
            del _rate_limit[k]
        if ip in _rate_limit:
            count, first_ts = _rate_limit[ip]
            if count >= RATE_LIMIT_MAX_FAILURES:
                return False
        return True


def record_login_failure(ip: str) -> None:
    """Record a failed login attempt for rate limiting."""
    lock = _get_lock()
    now = time.time()
    with lock:
        if ip in _rate_limit:
            count, first_ts = _rate_limit[ip]
            if now - first_ts > RATE_LIMIT_WINDOW_SEC:
                _rate_limit[ip] = (1, now)
            else:
                _rate_limit[ip] = (count + 1, first_ts)
        else:
            _rate_limit[ip] = (1, now)


def clear_rate_limit(ip: str) -> None:
    """Clear rate limit for IP after successful login."""
    lock = _get_lock()
    with lock:
        _rate_limit.pop(ip, None)


def overwrite_password(new_password: str) -> Optional[str]:
    """
    Overwrite stored password without verifying current. For CLI reset only.
    Returns error message or None on success.
    """
    if not is_auth_enabled():
        return "认证功能未启用"
    err = _validate_password(new_password)
    if err:
        return err

    data_dir = _get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    cred_path = _get_credential_path()

    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        new_password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    salt_b64 = base64.standard_b64encode(salt).decode("ascii")
    hash_b64 = base64.standard_b64encode(derived).decode("ascii")
    content = f"{salt_b64}:{hash_b64}"

    try:
        tmp_path = cred_path.with_suffix(".tmp")
        tmp_path.write_text(content)
        tmp_path.chmod(0o600)
        tmp_path.replace(cred_path)
        _load_credential_from_file()
        return None
    except OSError as e:
        logger.error("Failed to write credential file: %s", e)
        return "密码保存失败"


def reset_password_cli() -> int:
    """Interactive CLI to reset password. Returns exit code."""
    _ensure_env_loaded()
    if not _is_auth_enabled_from_env():
        print("Error: Auth is not enabled. Set ADMIN_AUTH_ENABLED=true in .env", file=sys.stderr)
        return 1

    print("Enter new admin password (will not echo):", end=" ")
    pwd = getpass.getpass("")
    err = _validate_password(pwd)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    print("Confirm new password:", end=" ")
    pwd2 = getpass.getpass("")
    if pwd != pwd2:
        print("Error: Passwords do not match", file=sys.stderr)
        return 1

    err = overwrite_password(pwd)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    print("Password has been reset successfully.")
    return 0


def _main() -> int:
    """CLI entry: reset_password subcommand."""
    if len(sys.argv) > 1 and sys.argv[1] == "reset_password":
        return reset_password_cli()
    print("Usage: python -m src.auth reset_password", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(_main())
