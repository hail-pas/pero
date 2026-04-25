# Pero Example App

A FastAPI application demonstrating OAuth2 integration with Pero User Center.

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Pero User Center running on `localhost:8080`

## Setup

### 1. Install dependencies

```bash
cd examples/app
uv sync
```

### 2. Register the app with Pero

Run the setup script with an admin token:

```bash
ADMIN_TOKEN=<your-admin-token> ./setup.sh
```

This outputs `OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET` — export them:

```bash
# create with pero bootstrap
export OAUTH2_CLIENT_ID=""
export OAUTH2_CLIENT_SECRET=""
```

### 3. Run the app

```bash
uv run uvicorn main:app --port 9000 --reload
```

Open http://localhost:9000 in your browser.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PERO_BASE_URL` | `http://localhost:8080` | Pero User Center URL |
| `EXAMPLE_PORT` | `9000` | Port for this example app |
| `OAUTH2_CLIENT_ID` | *(required)* | OAuth2 client ID from setup |
| `OAUTH2_CLIENT_SECRET` | *(required)* | OAuth2 client secret from setup |
| `APP_SECRET` | `change-me-in-production` | App secret key |

## Flow

1. User clicks **Sign in with Pero** → redirected to Pero SSO login
2. User authenticates → redirected back with authorization code
3. App exchanges code for tokens (with PKCE)
4. App fetches userinfo and creates a session
5. User can view/edit their profile through the app
