from fastapi import APIRouter

router = APIRouter()


@router.get("/healthz")
async def health_check() -> dict[str, bool]:
    return {"ok": True}
