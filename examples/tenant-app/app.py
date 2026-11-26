"""Minimal confidential OIDC/BFF integration for Pero, including tenant switching and sync."""
import base64
import hashlib
import json
import os
import re
import secrets
import sys
from functools import lru_cache
from html import escape
from urllib.parse import quote_plus, urlencode

import jwt
import redis
import requests
from flask import Flask, abort, make_response, redirect, request, url_for
from jwt import PyJWKClient

ISSUER = os.environ["PERO_ISSUER"].rstrip("/")
CLIENT_ID = os.environ["PERO_CLIENT_ID"]
CLIENT_SECRET = os.environ["PERO_CLIENT_SECRET"]
# OAuth client_secret_basic uses form-encoded credentials before HTTP Basic.
CLIENT_AUTH = (quote_plus(CLIENT_ID), quote_plus(CLIENT_SECRET))
REDIRECT_URI = os.environ.get("PERO_REDIRECT_URI", "http://127.0.0.1:8092/callback")
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
SCOPES = os.environ.get("PERO_SCOPES", "openid profile email")
SECURE_COOKIE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
COOKIE = "pero_demo"
http = requests.Session()
store = redis.from_url(REDIS_URL, decode_responses=True)
app = Flask(__name__)


@lru_cache(maxsize=1)
def discovery():
    result = http.get(ISSUER + "/.well-known/openid-configuration", timeout=8)
    result.raise_for_status()
    body = result.json()
    if body["issuer"].rstrip("/") != ISSUER:
        raise RuntimeError("Unexpected issuer")
    return body


@lru_cache(maxsize=1)
def jwks():
    return PyJWKClient(discovery()["jwks_uri"])


def cookie_id():
    value = request.cookies.get(COOKIE, "")
    return value if re.fullmatch(r"[a-zA-Z0-9_-]{43}", value) else None


def session_key(sid):
    return "pero-demo:session:" + sid


def current_session():
    sid = cookie_id()
    raw = store.get(session_key(sid)) if sid else None
    return (sid, json.loads(raw)) if raw else (sid, None)


def save_session(sid, data):
    store.setex(session_key(sid), 7 * 24 * 3600, json.dumps(data))


def client_post(endpoint, form):
    result = http.post(discovery()[endpoint], data=form,
                       auth=CLIENT_AUTH, timeout=10)
    result.raise_for_status()
    return result.json() if result.content else {}


def introspect(data):
    value = client_post("introspection_endpoint", {"token": data["access_token"]})
    if not value.get("active") or value.get("client_id") != CLIENT_ID:
        return None
    if (value.get("sub") != data["sub"] or value.get("tenant_id") != data["tenant_id"]
            or not data.get("sid") or value.get("sid") != data["sid"]):
        return None
    return value


def with_browser_session(response, sid):
    response.set_cookie(COOKIE, sid, httponly=True, secure=SECURE_COOKIE,
                        samesite="Lax", max_age=7 * 24 * 3600, path="/")
    return response


def start_login(tenant=None, create=False):
    previous_sid = cookie_id()
    sid = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    store.setex("pero-demo:flow:" + state, 600, json.dumps(
        {"sid": sid, "previous_sid": previous_sid, "verifier": verifier, "nonce": nonce,
         "tenant_id": tenant, "create": create}))
    params = {
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code",
        "scope": SCOPES, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if tenant:
        params["tenant_id"] = tenant
    if create:
        params["prompt"] = "create"
    return with_browser_session(
        redirect(discovery()["authorization_endpoint"] + "?" + urlencode(params)), sid)


@app.get("/login")
def login():
    tenant = request.args.get("tenant_id")
    if tenant and not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", tenant):
        abort(400)
    status = request.args.get("enrollment_status")
    if status in ("cancelled", "expired"):
        message = "Registration cancelled." if status == "cancelled" else "Registration authorization expired."
        return ('<p>' + message + '</p><a href="' + escape(url_for("login", tenant_id=tenant)) + '">Sign in</a> · '
                '<a href="/register">Start registration</a>')
    # Use the existing CSRF-protected switch when a signed-in user follows an invitation.
    _sid, data, _status = verified()
    if data:
        if tenant and tenant != data["tenant_id"]:
            return ('<form method="post" action="/switch">'
                    '<input type="hidden" name="csrf" value="' + escape(data["csrf"]) + '">'
                    '<input type="hidden" name="tenant" value="' + escape(tenant) + '">'
                    '<button type="submit">Continue to the invited workspace</button></form>')
        return redirect("/")
    return start_login(tenant)


@app.get("/register")
def register():
    _sid, data, _status = verified()
    return redirect("/") if data else start_login(create=True)


@app.get("/callback")
def callback():
    state = request.args.get("state", "")
    if not state:
        return ("Missing authorization state", 400)
    key = "pero-demo:flow:" + state
    value = store.get(key)
    if not value:
        return ("Expired authorization", 400)
    flow = json.loads(value)
    if cookie_id() != flow["sid"]:
        return ("Browser session changed", 403)
    if not store.getdel(key):
        return ("Expired authorization", 400)
    if error := request.args.get("error"):
        response = (redirect(url_for("login", enrollment_status="cancelled", tenant_id=flow["tenant_id"]))
                    if error == "access_denied" and flow["create"]
                    else make_response("Authorization declined", 400))
        if previous_sid := flow["previous_sid"]:
            return with_browser_session(response, previous_sid)
        return response
    if not request.args.get("code"):
        return ("Missing authorization code", 400)
    tokens = client_post("token_endpoint", {
        "grant_type": "authorization_code", "code": request.args["code"],
        "redirect_uri": REDIRECT_URI, "code_verifier": flow["verifier"],
    })
    id_token = tokens["id_token"]
    header = jwt.get_unverified_header(id_token)
    if header.get("alg") != "RS256":
        abort(401)
    claims = jwt.decode(id_token, jwks().get_signing_key_from_jwt(id_token).key,
                        algorithms=["RS256"], issuer=ISSUER, audience=CLIENT_ID,
                        options={"require": ["iss", "sub", "aud", "exp", "iat"]})
    if claims.get("nonce") != flow["nonce"] or not claims.get("sid"):
        abort(401)
    access_hash = base64.urlsafe_b64encode(
        hashlib.sha256(tokens["access_token"].encode()).digest()[:16]).rstrip(b"=").decode()
    if claims.get("at_hash") != access_hash:
        abort(401)
    snapshot = client_post("introspection_endpoint", {"token": tokens["access_token"]})
    if (not snapshot.get("active") or snapshot.get("client_id") != CLIENT_ID
            or snapshot.get("sub") != claims["sub"] or snapshot.get("sid") != claims["sid"]
            or not snapshot.get("tenant_id") or snapshot["tenant_id"] != claims.get("tenant_id")
            or (flow.get("tenant_id") and snapshot["tenant_id"] != flow["tenant_id"])):
        abort(403)
    session = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "id_token": id_token, "sub": claims["sub"], "sid": claims["sid"],
        "tenant_id": snapshot["tenant_id"],
        "csrf": secrets.token_urlsafe(32),
    }
    save_session(flow["sid"], session)
    previous_sid = flow.get("previous_sid")
    if previous_sid and previous_sid != flow["sid"]:
        store.delete(session_key(previous_sid))
    return redirect("/")


def verified():
    sid, data = current_session()
    if not data:
        return sid, None, None
    try:
        status = introspect(data)
    except requests.RequestException:
        abort(503)  # Dependency failure is not an invalid login.
    if status is None:
        store.delete(session_key(sid))
        return sid, None, None
    return sid, data, status


@app.get("/")
def home():
    _sid, data, status = verified()
    if not data:
        return '<a href="/login">Sign in with Pero</a> · <a href="/register">Create an account</a>'
    try:
        choices = http.get(ISSUER + "/api/tenants/choices",
                           headers={"Authorization": "Bearer " + data["access_token"]},
                           timeout=10)
        choices.raise_for_status()
        rows = choices.json().get("rows", [])
    except requests.RequestException:
        abort(503)
    body = "<h1>Pero connected application</h1>"
    body += "<p>User: " + escape(status["sub"]) + "</p>"
    body += "<p>Current tenant: " + escape(status["tenant_id"]) + "</p>"
    body += "<p>Tenant kind: " + escape(str(status.get("tenant_kind", ""))) + "</p>"
    body += "<p>Membership role: " + escape(str(status.get("membership_role", ""))) + "</p>"
    body += "<h2>Switch workspace</h2>"
    for row in rows:
        body += (
            '<form method="post" action="/switch">'
            '<input type="hidden" name="csrf" value="' + escape(data["csrf"]) + '">'
            '<input type="hidden" name="tenant" value="' + escape(row["id"]) + '">'
            '<button type="submit">' + escape(row["name"]) + '</button></form>'
        )
    body += '<form method="post" action="/logout"><input type="hidden" name="csrf" value="' + escape(data["csrf"]) + '"><button>Sign out</button></form>'
    return body


@app.post("/switch")
def switch():
    _sid, data, _status = verified()
    if not data:
        return redirect("/login")
    if not secrets.compare_digest(request.form.get("csrf", ""), data["csrf"]):
        abort(403)
    tenant = request.form.get("tenant", "")
    if not re.fullmatch(r"[a-f0-9-]{36}", tenant):
        abort(400)
    result = http.get(ISSUER + "/api/tenants/choices",
                      headers={"Authorization": "Bearer " + data["access_token"]}, timeout=10)
    result.raise_for_status()
    if tenant not in {row["id"] for row in result.json()["rows"]}:
        abort(403)
    return start_login(tenant)


@app.post("/logout")
def logout():
    sid, data = current_session()
    if not data or not secrets.compare_digest(request.form.get("csrf", ""), data["csrf"]):
        abort(403)
    # This revokes the application's grant; a failure must not hide the token locally.
    client_post("revocation_endpoint", {"token": data.get("refresh_token") or data["access_token"]})
    store.delete(session_key(sid))
    response = redirect(discovery()["end_session_endpoint"] + "?" + urlencode({
        "id_token_hint": data["id_token"],
    }))
    response.delete_cookie(COOKIE, path="/")
    return response


def verify_event(token):
    header = jwt.get_unverified_header(token)
    if header.get("typ") != "pero-account-sync+jwt" or header.get("alg") != "RS256":
        abort(401)
    event = jwt.decode(token, jwks().get_signing_key_from_jwt(token).key,
                       algorithms=["RS256"], issuer=ISSUER, audience=CLIENT_ID,
                       options={"require": ["iss", "aud", "sub", "exp", "iat", "jti"]})
    if event.get("event") not in {
        "sync.requested", "account.updated", "account.status_changed", "account.deleted",
        "membership.granted", "membership.revoked", "tenant.membership.changed",
    }:
        abort(400)
    return event



def snapshot(path, params):
    base = ISSUER + path
    response = http.post(base, data=params, auth=CLIENT_AUTH, timeout=10)
    response.raise_for_status()
    return response.json()


@app.post("/account-sync")
def account_sync():
    token = request.form.get("event_token", "")
    try:
        event = verify_event(token)
        jti = event["jti"]
        if store.exists("pero-demo:seen:" + jti):
            return ("", 200)
        if event["event"] == "tenant.membership.changed":
            tenant = event.get("tenant_id")
            if not tenant:
                abort(400)
            projection = snapshot("/api/tenants/membership/sync",
                                  {"sub": event["sub"], "tenant_id": tenant})
            key = "pero-demo:membership:" + tenant + ":" + event["sub"]
        else:
            projection = snapshot("/api/accounts/sync", {"sub": event["sub"]})
            key = "pero-demo:account:" + event["sub"]
        store.set(key, json.dumps(projection))
        store.setex("pero-demo:seen:" + jti, 3 * 24 * 3600, "1")
        return ("", 200)
    except requests.RequestException:
        return ("Service temporarily unavailable", 503)


def reconcile():
    """Full keyset catch-up after webhook downtime or first integration."""
    for url, cursor in [
        ("/api/accounts/sync/list", ["after_user_id"]),
        ("/api/tenants/list", ["after_tenant_id"]),
        ("/api/tenants/membership/list", ["after_tenant_id", "after_user_id"]),
    ]:
        params = {}
        while True:
            data = snapshot(url, params)
            for row in data["rows"]:
                if url.startswith("/api/accounts"):
                    key = "pero-demo:account:" + row["sub"]
                elif url.endswith("membership/list"):
                    key = "pero-demo:membership:" + row["tenant_id"] + ":" + row["sub"]
                else:
                    key = "pero-demo:tenant:" + row["tenant_id"]
                store.set(key, json.dumps(row))
            if not data["next"]:
                break
            params = ({cursor[0]: data["next"]} if len(cursor) == 1 else {
                "after_tenant_id": data["next"]["tenant_id"],
                "after_user_id": data["next"]["user_id"],
            })


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reconcile":
        reconcile()
    else:
        app.run(host="127.0.0.1", port=8092, debug=False)
