import time
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.settings import get_settings

_jwks_cache: Dict[str, Any] = {"keys": None, "expires_at": 0.0}
_jwks_ttl_seconds = 300
_bearer_scheme = HTTPBearer(auto_error=False)


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


async def require_auth(credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme)) -> Dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing.")

    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not provided.")

    settings = get_settings()
    if settings.auth_token and token == settings.auth_token:
        return {"sub": "internal-service", "token_type": "static"}

    return await _verify_jwt(token)
