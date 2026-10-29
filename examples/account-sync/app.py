"""Mount behind HTTPS; replace the stored projection with your application's account update."""
import json
import os
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
import redis
from flask import Flask, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16384
issuer = os.environ["OIDC_ISSUER"]
client_id = os.environ["OIDC_CLIENT_ID"]
client_secret = os.environ["OIDC_CLIENT_SECRET"]
if not issuer.startswith("https://"):
    raise ValueError("OIDC_ISSUER must use HTTPS")
jwks = jwt.PyJWKClient(issuer.rstrip("/") + "/api/oauth2/jwks", lifespan=60)
store = redis.Redis.from_url(os.environ["REDIS_URL"])
prefix = "rp:" + client_id + ":"
events = {
    "sync.requested", "account.updated", "account.status_changed",
    "account.deleted", "membership.granted", "membership.revoked",
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward client credentials to another endpoint.


http = build_opener(NoRedirect())


@app.post("/account-sync")
def synchronize():
    token = request.form.get("event_token", "")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "pero-account-sync+jwt" or header.get("alg") != "RS256":
            return "invalid token type", 400
        claims = jwt.decode(
            token, jwks.get_signing_key_from_jwt(token).key,
            algorithms=["RS256"], audience=client_id, issuer=issuer, leeway=30,
            options={"require": ["iss", "aud", "sub", "iat", "exp", "jti", "event", "occurred_at"]},
        )
        if "nonce" in claims or claims["event"] not in events or claims["iat"] < time.time() - 180:
            return "invalid event", 400
        sub, jti = str(uuid.UUID(claims["sub"])), str(uuid.UUID(claims["jti"]))
    except jwt.PyJWKClientConnectionError:
        return "keys unavailable", 503
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        return "invalid event token", 400

    try:
        # Serialize fetch + apply by subject, so concurrent requests cannot apply stale snapshots.
        with store.lock(prefix + "sync-lock:" + sub, timeout=30, blocking_timeout=0):
            seen = prefix + "sync-event:" + jti
            if store.exists(seen):
                return "", 200
            body = urlencode({"sub": sub, "client_id": client_id, "client_secret": client_secret}).encode()
            with http.open(Request(issuer.rstrip("/") + "/api/accounts/sync", data=body), timeout=10) as response:
                snapshot = json.load(response)
            if snapshot["sub"] != sub or not isinstance(snapshot["active"], bool):
                return "invalid snapshot", 503
            # Replace this transaction with your local DB transaction. Commit the account
            # projection and the consumed jti together; never use email to merge accounts.
            with store.pipeline(transaction=True) as transaction:
                transaction.set(prefix + "account:" + sub, json.dumps(snapshot))
                transaction.set(seen, "1", ex=172800)
                transaction.execute()
    except (HTTPError, URLError, TimeoutError, ValueError, KeyError, redis.RedisError):
        return "synchronization unavailable", 503
    return "", 200
