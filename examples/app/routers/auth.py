from datetime import datetime, timezone
import urllib.parse

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

import config
from services import oauth2

router = APIRouter()

_sessions: dict[str, dict] = {}

SESSION_COOKIE = "example_session"
PKCE_COOKIE = "example_pkce"


def _get_session(request: Request) -> dict | None:
    sid = request.cookies.get(SESSION_COOKIE)
    if sid and sid in _sessions:
        return _sessions[sid]
    return None


def _start_oauth(response: RedirectResponse, verifier: str):
    response.set_cookie(
        PKCE_COOKIE,
        verifier,
        httponly=True,
        max_age=600,
        samesite="lax",
    )


@router.get("/login")
async def login():
    verifier, challenge = oauth2.generate_pkce()
    state = oauth2.generate_state()
    url = oauth2.build_authorize_url(state, challenge)
    redirect = RedirectResponse(url=url, status_code=302)
    _start_oauth(redirect, verifier)
    return redirect


@router.get("/social-login")
async def social_login(provider: str = Query(...)):
    verifier, challenge = oauth2.generate_pkce()
    state = oauth2.generate_state()
    params = {
        "client_id": config.OAUTH2_CLIENT_ID,
        "redirect_uri": config.REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "login_hint": provider,
    }
    url = f"{config.PERO_BASE_URL}/oauth2/authorize?{urllib.parse.urlencode(params)}"
    redirect = RedirectResponse(url=url, status_code=302)
    _start_oauth(redirect, verifier)
    return redirect


@router.get("/api/social-providers")
async def api_social_providers():
    try:
        providers = await oauth2.get_social_providers()
        return JSONResponse(content={"data": providers})
    except Exception:
        return JSONResponse(content={"data": []})


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
):
    if error:
        desc = error_description or error
        return RedirectResponse(url=f"/?error={desc}", status_code=302)

    verifier = request.cookies.get(PKCE_COOKIE)
    if not verifier:
        return RedirectResponse(
            url="/?error=Expired+or+invalid+request", status_code=302
        )

    try:
        token_data = await oauth2.exchange_code(code, verifier)
    except Exception as exc:
        return RedirectResponse(
            url=f"/?error=Token+exchange+failed:+{exc}", status_code=302
        )

    access_token = token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    id_token = token_data.get("id_token", "")

    try:
        userinfo = await oauth2.get_userinfo(access_token)
    except Exception as exc:
        return RedirectResponse(
            url=f"/?error=Userinfo+fetch+failed:+{exc}", status_code=302
        )

    session_id = __import__("secrets").token_urlsafe(32)
    _sessions[session_id] = {
        "user_info": userinfo,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    redirect = RedirectResponse(url="/?page=profile", status_code=302)
    redirect.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        max_age=86400,
        samesite="lax",
    )
    redirect.delete_cookie(PKCE_COOKIE)
    return redirect


@router.get("/logout")
async def logout(request: Request):
    session = _get_session(request)
    id_token_hint = ""
    if session:
        id_token_hint = session.get("id_token", "")
        refresh = session.get("refresh_token")
        if refresh:
            try:
                await oauth2.revoke_token(refresh)
            except Exception:
                pass
        sid = request.cookies.get(SESSION_COOKIE)
        if sid:
            _sessions.pop(sid, None)

    redirect = RedirectResponse(url="/", status_code=302)
    redirect.delete_cookie(SESSION_COOKIE)

    if id_token_hint:
        params = {
            "id_token_hint": id_token_hint,
            "post_logout_redirect_uri": f"http://localhost:{config.EXAMPLE_PORT}/",
        }
        import urllib.parse
        end_session_url = f"{config.PERO_BASE_URL}/oauth2/session/end?{urllib.parse.urlencode(params)}"
        redirect = RedirectResponse(url=end_session_url, status_code=302)
        redirect.delete_cookie(SESSION_COOKIE)

    return redirect


@router.get("/api/me")
async def get_me(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    try:
        profile = await oauth2.get_profile(session["access_token"])
        session["user_info"] = profile
        return JSONResponse(content=profile)
    except Exception:
        return JSONResponse(content=session["user_info"])

@router.post("/api/permission/check")
async def check_permission_api(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    body = await request.json()
    resource = body.get("resource", "")
    action = body.get("action", "GET")
    if not resource:
        return JSONResponse(status_code=400, content={"error": "resource is required"})

    try:
        allowed = await oauth2.check_permission(
            session["access_token"], resource, action
        )
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})

    return JSONResponse(
        content={"resource": resource, "action": action, "allowed": allowed}
    )


@router.get("/api/protected/orders")
async def list_orders(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    allowed = await oauth2.check_permission(
        session["access_token"], "/api/protected/orders", "GET"
    )
    if not allowed:
        return JSONResponse(
            status_code=403, content={"error": "Access denied by policy"}
        )

    return JSONResponse(
        content={
            "orders": [
                {
                    "id": "ORD-001",
                    "item": "Widget A",
                    "quantity": 10,
                    "status": "shipped",
                },
                {
                    "id": "ORD-002",
                    "item": "Widget B",
                    "quantity": 5,
                    "status": "pending",
                },
                {
                    "id": "ORD-003",
                    "item": "Widget C",
                    "quantity": 2,
                    "status": "delivered",
                },
            ]
        }
    )


@router.post("/api/protected/orders")
async def create_order(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    allowed = await oauth2.check_permission(
        session["access_token"], "/api/protected/orders", "POST"
    )
    if not allowed:
        return JSONResponse(
            status_code=403, content={"error": "Access denied by policy"}
        )

    body = await request.json()
    return JSONResponse(
        content={
            "id": "ORD-NEW",
            "item": body.get("item", "Unknown"),
            "quantity": body.get("quantity", 0),
            "status": "created",
        }
    )
