"""Password hashing, JWT sessions with real revocation, role checks, bootstrap admin."""
import hashlib
import hmac
import logging
import os
import secrets
import time
import uuid
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException, Request

from . import db

log = logging.getLogger("auth")

DEFAULT_TENANT = "default"
ROLES = ("admin", "reviewer", "viewer", "analyst", "governance_owner")
ROLE_ALIAS = {"analyst": "reviewer", "governance_owner": "reviewer"}  # same write rights as a reviewer
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "28800"))
_ITER = 200_000


def _secret() -> str:
    env = os.getenv("SECRET_KEY")
    if env:
        return env
    doc = db.get("settings", "_global", "jwt_secret")
    if not doc:
        doc = db.put("settings", "_global", "jwt_secret", {"value": secrets.token_urlsafe(48)})
    return doc["value"]


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITER).hex()
    return f"pbkdf2${_ITER}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters)).hex()
        return hmac.compare_digest(calc, digest)
    except Exception:
        return False


def issue_token(user: dict) -> dict:
    exp = int(time.time()) + TOKEN_TTL
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "tenant_id": user["tenant_id"],
        "jti": uuid.uuid4().hex,
        "exp": exp,
    }
    token = jwt.encode(payload, _secret(), algorithm="HS256")
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "tenant_id": user["tenant_id"],
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)),
    }


def decode_token(token: str) -> Optional[dict]:
    try:
        p = jwt.decode(token, _secret(), algorithms=["HS256"])
    except Exception:
        return None
    if db.get("revoked", "_global", p.get("jti", "")):
        return None
    return {
        "username": p["sub"],
        "role": p["role"],
        "tenant_id": p["tenant_id"],
        "jti": p["jti"],
        "exp": p["exp"],
    }


def revoke(user: dict) -> None:
    db.put("revoked", "_global", user["jti"], {"exp": user["exp"]})


def current_user(request: Request, authorization: Optional[str] = Header(None)) -> dict:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif request.query_params.get("token"):  # EventSource cannot send headers
        token = request.query_params["token"]
    user = decode_token(token) if token else None
    if not user:
        raise HTTPException(401, "Not authenticated")
    stored = db.get("users", "_global", user["username"])
    if not stored or stored.get("disabled"):
        raise HTTPException(401, "Account not available")
    user["role"] = stored["role"]
    user["tenant_id"] = stored["tenant_id"]
    return user


def require(*roles: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        eff = ROLE_ALIAS.get(user["role"], user["role"])
        if user["role"] not in roles and eff not in roles:
            raise HTTPException(403, f"Requires role: {', '.join(roles)}")
        return user

    return dep


def is_platform_admin(user: dict) -> bool:
    return user["role"] == "admin" and user["tenant_id"] == DEFAULT_TENANT


def create_user(username: str, password: str, role: str, tenant_id: str, validate: bool = True) -> dict:
    if role not in ROLES:
        raise HTTPException(400, f"role must be one of {ROLES}")
    if validate:
        if len(username) < 3 or not username.replace("_", "").replace(".", "").replace("-", "").isalnum():
            raise HTTPException(400, "username must be 3+ chars, letters/digits/._-")
        if len(password) < 8:
            raise HTTPException(400, "password must be at least 8 characters")
    if db.get("users", "_global", username):
        raise HTTPException(409, "username already exists")
    doc = {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "tenant_id": tenant_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    db.put("users", "_global", username, doc)
    return doc


def public_user(u: dict) -> dict:
    return {k: u[k] for k in ("username", "role", "tenant_id", "created_at") if k in u}


def bootstrap() -> None:
    """Create the default tenant and first admin on an empty database."""
    if not db.get("tenants", "_global", DEFAULT_TENANT):
        db.put(
            "tenants",
            "_global",
            DEFAULT_TENANT,
            {"id": DEFAULT_TENANT, "name": "Default tenant", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        )
    if db.count("users", "_global") == 0:
        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD")
        generated = False
        if not password:
            password = secrets.token_urlsafe(14)
            generated = True
        create_user(username, password, "admin", DEFAULT_TENANT, validate=False)
        if generated:
            log.warning("BOOTSTRAP ADMIN CREATED  username=%s  password=%s  (set ADMIN_PASSWORD to choose your own)", username, password)
        else:
            log.warning("Bootstrap admin '%s' created from ADMIN_PASSWORD", username)
