"""Password hashes and short-lived identity tokens, never client-supplied roles."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def verify_password(password, encoded):
    try:
        algorithm, rounds, salt, digest = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or rounds != "600000":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
        return hmac.compare_digest(actual.hex(), digest)
    except (ValueError, TypeError):
        return False


def issue_token(subject, secret, auth_version, device_serial=None, tenant_id="demo"):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": subject,
            "tenant_id": tenant_id,
            "iss": "abac-gateway",
            "aud": "abac-data",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=10),
            "jti": secrets.token_hex(16),
            "auth_version": auth_version,
            "device_serial": device_serial,
        },
        secret,
        algorithm="HS256",
    )


def decode_token(token, secret):
    claims = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer="abac-gateway",
        audience="abac-data",
        options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti", "auth_version"]},
    )
    if (
        type(claims["auth_version"]) is not int
        or claims["auth_version"] < 1
        or not isinstance(claims["jti"], str)
        or len(claims["jti"]) != 32
        or "device_serial" not in claims
        or not isinstance(claims.get("tenant_id"), str)
        or (
            claims["device_serial"] is not None
            and (not isinstance(claims["device_serial"], str) or len(claims["device_serial"]) > 64)
        )
    ):
        raise jwt.InvalidTokenError("Invalid identity/session contract")
    return claims
