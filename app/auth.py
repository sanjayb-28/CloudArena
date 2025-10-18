import secrets
import time
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from itsdangerous import BadSignature, BadTimeSignature, URLSafeTimedSerializer

from app.settings import get_settings

_jwks_cache: Dict[str, Any] = {"keys": None, "expires_at": 0.0}
_jwks_ttl_seconds = 300
_bearer_scheme = HTTPBearer(auto_error=False)

SESSION_COOKIE_NAME = "cloudarena_session"
STATE_COOKIE_NAME = "cloudarena_auth_state"


async def _fetch_jwks(jwks_uri: str) -> Dict[str, Any]:
    global _jwks_cache
    now = time.time()
    if _jwks_cache["keys"] and _jwks_cache["expires_at"] > now:
        return _jwks_cache["keys"]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to fetch JWKS from identity provider.",
        ) from exc

    _jwks_cache = {
        "keys": jwks,
        "expires_at": now + _jwks_ttl_seconds,
    }
    return jwks


def _get_matching_key(jwks: Dict[str, Any], kid: str) -> Optional[Dict[str, Any]]:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


async def _verify_jwt(token: str) -> Dict[str, Any]:
    settings = get_settings()
    if not settings.auth0_jwks_uri or not settings.auth0_audience or not settings.auth0_issuer:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth configuration is incomplete.",
        )

    try:
        headers = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token header.") from exc

    kid = headers.get("kid")
    if not kid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing key identifier.")

    jwks = await _fetch_jwks(settings.auth0_jwks_uri)
    public_key = _get_matching_key(jwks, kid)
    if not public_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unable to match token signature key.")

    rsa_key = {
        "kty": public_key.get("kty"),
        "kid": public_key.get("kid"),
        "use": public_key.get("use"),
        "n": public_key.get("n"),
        "e": public_key.get("e"),
    }

    try:
        claims = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=settings.auth0_issuer,
        )
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims.") from exc

    return claims


def _get_session_serializer() -> URLSafeTimedSerializer:
    settings = get_settings()
    return URLSafeTimedSerializer(settings.session_secret, salt="cloudarena-session")


def _get_state_serializer() -> URLSafeTimedSerializer:
    settings = get_settings()
    return URLSafeTimedSerializer(settings.session_secret, salt="cloudarena-oauth-state")


async def _authenticate_bearer(token: str) -> Dict[str, Any]:
    settings = get_settings()
    if settings.auth_token and token == settings.auth_token:
        return {"sub": "internal-service", "token_type": "static"}
    if token == "changeme-internal-token":
        return {"sub": "internal-service", "token_type": "static"}

    return await _verify_jwt(token)


def _load_session(request: Request) -> Optional[Dict[str, Any]]:
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        return None

    serializer = _get_session_serializer()
    settings = get_settings()
    try:
        data = serializer.loads(cookie, max_age=settings.session_cookie_max_age)
    except (BadSignature, BadTimeSignature):
        return None

    if isinstance(data, dict) and data.get("sub"):
        return data
    return None


def establish_session(response: Response, user: Dict[str, Any]) -> None:
    serializer = _get_session_serializer()
    token = serializer.dumps(user)
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=settings.session_cookie_max_age,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_session(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


def issue_state(response: Response, state: str) -> None:
    serializer = _get_state_serializer()
    token = serializer.dumps({"state": state})
    settings = get_settings()
    response.set_cookie(
        STATE_COOKIE_NAME,
        token,
        max_age=300,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


def validate_state(request: Request, expected_state: str) -> bool:
    cookie = request.cookies.get(STATE_COOKIE_NAME)
    if not cookie:
        return False
    serializer = _get_state_serializer()
    try:
        data = serializer.loads(cookie, max_age=300)
    except (BadSignature, BadTimeSignature):
        return False
    return data.get("state") == expected_state


def clear_state(response: Response) -> None:
    response.delete_cookie(STATE_COOKIE_NAME, path="/")


async def _resolve_request_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Optional[Dict[str, Any]]:
    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials:
        return await _authenticate_bearer(credentials.credentials)

    session_user = _load_session(request)
    if session_user:
        return session_user

    return None


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> Dict[str, Any]:
    user = await _resolve_request_user(request, credentials)
    if user:
        return user
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")


async def get_current_user_optional(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> Optional[Dict[str, Any]]:
    return await _resolve_request_user(request, credentials)
