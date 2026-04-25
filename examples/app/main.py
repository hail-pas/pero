from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from routers import auth, user

app = FastAPI(title="Pero Example App")

app.include_router(auth.router)
app.include_router(user.router)

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def index():
    from fastapi.responses import FileResponse

    return FileResponse(static_dir / "index.html")
