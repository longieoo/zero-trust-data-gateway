"""Authenticated keyset cursors bound to session, identity and policy revision."""

import hashlib
import json

import jwt


def binding(subject, session_id, resource, revision, page_size):
    return hashlib.sha256(
        json.dumps(
            [subject, session_id, resource, revision, page_size],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def issue_cursor(secret, subject, session_id, resource, revision, page_size, last_id, now):
    return jwt.encode(
        {
            "b": binding(subject, session_id, resource, revision, page_size),
            "last_id": last_id,
            "exp": int(now.timestamp()) + 600,
            "aud": "gateway-pagination",
        },
        secret,
        algorithm="HS256",
    )


def read_cursor(token, secret, subject, session_id, resource, revision, page_size, now):
    if not isinstance(token, str) or len(token) > 2048:
        raise ValueError("Invalid cursor")
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="gateway-pagination",
            options={"require": ["b", "last_id", "exp", "aud"], "verify_exp": False},
        )
        if (
            type(claims["exp"]) is not int
            or claims["exp"] <= now.timestamp()
            or type(claims["last_id"]) is not int
            or not 0 < claims["last_id"] <= 2**31 - 1
            or claims["b"] != binding(subject, session_id, resource, revision, page_size)
        ):
            raise ValueError("Expired or mismatched cursor")
        return claims["last_id"]
    except jwt.PyJWTError as exc:
        raise ValueError("Invalid cursor") from exc
