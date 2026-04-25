import os

PERO_BASE_URL = os.getenv("PERO_BASE_URL", "http://localhost:8080")
EXAMPLE_PORT = int(os.getenv("EXAMPLE_PORT", "9000"))

OAUTH2_CLIENT_ID = os.getenv("OAUTH2_CLIENT_ID", "")
OAUTH2_CLIENT_SECRET = os.getenv("OAUTH2_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"http://localhost:{EXAMPLE_PORT}/callback")

APP_SECRET = os.getenv("APP_SECRET", "change-me-in-production")
