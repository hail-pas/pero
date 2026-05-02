import base64
import hashlib
import os
import secrets
import urllib.parse

import httpx

import config


def _basic_auth_header() -> dict[str, str]:
    token = base64.b64encode(
        f"{config.OAUTH2_CLIENT_ID}:{config.OAUTH2_CLIENT_SECRET}".encode()
    ).decode()
    return {"Authorization": f"Basic {token}"}


def generate_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def build_authorize_url(state: str, code_challenge: str) -> str:
    params = {
        "client_id": config.OAUTH2_CLIENT_ID,
        "redirect_uri": config.REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{config.PERO_BASE_URL}/oauth2/authorize?{urllib.parse.urlencode(params)}"


async def exchange_code(code: str, code_verifier: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.PERO_BASE_URL}/oauth2/token",
            headers=_basic_auth_header(),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.REDIRECT_URI,
                "code_verifier": code_verifier,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def get_userinfo(access_token: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{config.PERO_BASE_URL}/oauth2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def refresh_token(refresh_token: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.PERO_BASE_URL}/oauth2/token",
            headers=_basic_auth_header(),
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        resp.raise_for_status()
        return resp.json()


async def revoke_token(token: str) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.PERO_BASE_URL}/oauth2/revoke",
            headers=_basic_auth_header(),
            data={
                "token": token,
            },
        )
        resp.raise_for_status()


async def get_profile(access_token: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{config.PERO_BASE_URL}/api/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body)


async def check_permission(access_token: str, resource: str, action: str) -> bool:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.PERO_BASE_URL}/api/abac/evaluate",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"resource": resource, "action": action},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", {}).get("allowed", False)


async def get_social_providers() -> list[dict]:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{config.PERO_BASE_URL}/api/social-providers/enabled",
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", [])
