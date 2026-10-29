"""RP example: mount behind HTTPS and use the same Redis store as app sessions."""
import os
import time
import uuid

import jwt
import redis
from flask import Flask, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16384
issuer = os.environ["OIDC_ISSUER"]
client_id = os.environ["OIDC_CLIENT_ID"]
# Fixed trusted URL, never a jku/x5u supplied by an incoming JWT.
jwks = jwt.PyJWKClient(issuer.rstrip("/") + "/api/oauth2/jwks", lifespan=60)
store = redis.Redis.from_url(os.environ["REDIS_URL"])
prefix = "rp:" + client_id + ":"

# In the application's OIDC callback, after verifying the ID Token, store:
#   SET <prefix>session:<local_session_id> <your-session-data> EX <session-ttl>
#   SADD <prefix>oidc:<id_token.sid> <local_session_id>
#   EXPIRE <prefix>oidc:<id_token.sid> <maximum-local-session-ttl>
# Every authenticated request must read the server-side session. Stateless local
# cookies alone cannot be invalidated by a server-to-server logout request.
invalidate = store.register_script("""
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
local sessions = redis.call('SMEMBERS', KEYS[2])
for _, id in ipairs(sessions) do redis.call('DEL', ARGV[1] .. 'session:' .. id) end
redis.call('DEL', KEYS[2])
redis.call('SET', KEYS[1], '1', 'EX', 172800)
return 1
""")


@app.post("/backchannel-logout")
def logout():
    token = request.form.get("logout_token", "")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "logout+jwt" or header.get("alg") != "RS256":
            return "invalid token type", 400
        key = jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=client_id,
            issuer=issuer, leeway=30,
            options={"require": ["iss", "aud", "iat", "exp", "jti", "sid", "sub", "events"]},
        )
        if ("nonce" in claims or claims["events"] != {
            "http://schemas.openid.net/event/backchannel-logout": {}
        } or claims["iat"] < time.time() - 180):
            return "invalid logout claims", 400
        sid = str(uuid.UUID(claims["sid"]))
        jti = str(uuid.UUID(claims["jti"]))
        # Deletion and replay acknowledgement commit atomically. A failed store
        # write returns 503 so Pero retries; duplicates/unknown sessions return 200.
        invalidate(keys=[prefix + "logout:" + jti, prefix + "oidc:" + sid], args=[prefix])
    except jwt.PyJWKClientConnectionError:
        return "keys unavailable", 503
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        return "invalid logout token", 400
    except redis.RedisError:
        return "session store unavailable", 503
    return "", 200
