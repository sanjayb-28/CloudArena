import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from app.auth import (
    clear_session,
    clear_state,
    establish_session,
    get_current_user_optional,
    issue_state,
    validate_state,
)
from app.settings import get_settings

router = APIRouter()


def _build_redirect_uri(request: Request) -> str:
    settings = get_settings()
    if settings.auth0_callback_url:
        return settings.auth0_callback_url
    return str(request.url_for("auth_callback"))


@router.get("/login")
async def login(request: Request, user=Depends(get_current_user_optional)) -> RedirectResponse:
    if user:
        return RedirectResponse(url="/ui", status_code=status.HTTP_303_SEE_OTHER)

    settings = get_settings()
    if not settings.auth0_domain or not settings.auth0_client_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Auth0 login not configured.")

    state = secrets.token_urlsafe(32)
    redirect_uri = _build_redirect_uri(request)
    params = {
        "response_type": "code",
        "client_id": settings.auth0_client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
    }
    if settings.auth0_audience:
        params["audience"] = settings.auth0_audience

    authorization_url = f"https://{settings.auth0_domain}/authorize?{urlencode(params)}"
    redirect = RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)
    issue_state(redirect, state)
    return redirect


@router.get("/auth/callback", name="auth_callback")
async def auth_callback(
    request: Request,
    code: str,
    state: str,
) -> RedirectResponse:
    settings = get_settings()

    if not validate_state(request, state):
        redirect = RedirectResponse(url="/login?error=state", status_code=status.HTTP_303_SEE_OTHER)
        clear_state(redirect)
        return redirect

    if not settings.auth0_domain or not settings.auth0_client_id or not settings.auth0_client_secret:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Auth0 login not configured.")

    redirect_uri = _build_redirect_uri(request)
    token_url = f"https://{settings.auth0_domain}/oauth/token"
    token_payload = {
        "grant_type": "authorization_code",
        "client_id": settings.auth0_client_id,
        "client_secret": settings.auth0_client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_response = await client.post(token_url, data=token_payload)
        try:
            token_response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Auth0 token exchange failed.") from exc
        tokens = token_response.json()

        access_token = tokens.get("access_token")
        if not access_token:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Auth0 access token missing.")

        userinfo_url = f"https://{settings.auth0_domain}/userinfo"
        userinfo_response = await client.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
        try:
            userinfo_response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Auth0 userinfo request failed.") from exc
        profile = userinfo_response.json()

    user_claims = {
        "sub": profile.get("sub"),
        "name": profile.get("name") or profile.get("email") or "CloudArena User",
        "email": profile.get("email"),
    }
    if not user_claims["sub"]:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Auth0 response missing subject.")

    redirect = RedirectResponse(url="/ui", status_code=status.HTTP_303_SEE_OTHER)
    clear_state(redirect)
    establish_session(redirect, user_claims)
    return redirect


@router.get("/logout")
async def logout() -> RedirectResponse:
    redirect = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    clear_session(redirect)
    clear_state(redirect)
    return redirect
