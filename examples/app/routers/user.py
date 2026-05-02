from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

import config

router = APIRouter()


@router.get("/api/config")
async def get_config():
    return JSONResponse(content={"pero_base_url": config.PERO_BASE_URL})
