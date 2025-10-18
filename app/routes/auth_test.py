from fastapi import APIRouter, Depends

from app.auth import require_auth

router = APIRouter()


@router.get("/auth/test")
async def auth_test(claims: dict = Depends(require_auth)) -> dict:
    return {"sub": claims.get("sub")}
