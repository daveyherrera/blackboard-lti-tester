"""
BB LTI 1.3 Tester — FastAPI backend
"""
from __future__ import annotations
import asyncio, json, secrets, time, uuid
from pathlib import Path
from typing import Optional

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError, jwk
import base64

# ── Config ──────────────────────────────────────────────────────────────────

KEYS_DIR = Path("keys")
SETTINGS_FILE = Path("settings.json")
MAX_LAUNCHES = 100
STATE_TTL = 300  # 5 minutes
JWKS_CACHE_TTL = 3600  # 1 hour
GITHUB_PAGES_URL = "https://daveyherrera.github.io/blackboard-lti-tester"

DEFAULT_CONFIG = {
    "client_id": "",
    "deployment_id": "",
    "oidc_auth_url": "https://developer.blackboard.com/api/v1/gateway/oidcauth",
    "jwks_url": "https://developer.blackboard.com/api/v1/management/applications/keys",
    "issuer": "https://blackboard.com",
}

# ── In-memory state ──────────────────────────────────────────────────────────

pending_states: dict[str, dict] = {}
launches: list[dict] = []
jwks_cache: dict = {"keys": None, "fetched_at": 0}
config: dict = {}

# ── Startup helpers ───────────────────────────────────────────────────────────

def load_config() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(SETTINGS_FILE.read_text())}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_config(data: dict):
    SETTINGS_FILE.write_text(json.dumps(data, indent=2))

def ensure_keys() -> tuple[bytes, bytes]:
    """Generate RSA-2048 key pair if not present. Returns (private_pem, public_pem)."""
    KEYS_DIR.mkdir(exist_ok=True)
    priv_file = KEYS_DIR / "private.pem"
    pub_file = KEYS_DIR / "public.pem"
    if not priv_file.exists():
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        priv_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pub_file.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return priv_file.read_bytes(), pub_file.read_bytes()

def public_key_to_jwks(pub_pem: bytes) -> dict:
    """Convert RSA public key PEM to JWKS format."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    key = load_pem_public_key(pub_pem, backend=default_backend())
    numbers = key.public_numbers()

    def int_to_base64url(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "lti-tester-key-1",
                "n": int_to_base64url(numbers.n),
                "e": int_to_base64url(numbers.e),
            }
        ]
    }

# ── ngrok ────────────────────────────────────────────────────────────────────

async def get_ngrok_url() -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get("http://localhost:4040/api/tunnels")
            tunnels = r.json().get("tunnels", [])
            https = next(
                (t["public_url"] for t in tunnels if t["proto"] == "https"), None
            )
            return https
    except Exception:
        return None

# ── JWKS fetch ───────────────────────────────────────────────────────────────

async def fetch_jwks(force: bool = False) -> Optional[list]:
    """Fetch and cache Blackboard's JWKS. Returns list of keys or None on error."""
    now = time.time()
    if (
        not force
        and jwks_cache["keys"]
        and (now - jwks_cache["fetched_at"]) < JWKS_CACHE_TTL
    ):
        return jwks_cache["keys"]
    jwks_url = config.get("jwks_url")
    if not jwks_url:
        return None
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(jwks_url)
            r.raise_for_status()
            keys = r.json().get("keys", [])
            jwks_cache["keys"] = keys
            jwks_cache["fetched_at"] = now
            return keys
    except Exception:
        return jwks_cache.get("keys")  # return stale on error

# ── JWT validation ───────────────────────────────────────────────────────────

async def validate_lti_jwt(
    token: str, expected_nonce: str
) -> tuple[bool, dict, str]:
    """
    Validate an LTI 1.3 id_token.
    Returns (is_valid, payload_dict, error_message).
    """
    # 1. Decode header without verification to get kid
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as e:
        return False, {}, f"Cannot decode JWT header: {e}"

    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    if alg not in ("RS256", "RS512"):
        return False, {}, f"Unsupported algorithm: {alg}"

    # 2. Fetch JWKS and find matching key
    keys = await fetch_jwks()
    if not keys:
        return (
            False,
            {},
            "Cannot fetch Blackboard's JWKS — check JWKS URL in Settings",
        )

    signing_key = next((k for k in keys if k.get("kid") == kid), None)
    if not signing_key:
        # Try refetching (key may have rotated)
        keys = await fetch_jwks(force=True)
        signing_key = next(
            (k for k in (keys or []) if k.get("kid") == kid), None
        )
    if not signing_key:
        return False, {}, f"No JWKS key found for kid={kid!r}"

    # 3. Verify signature and standard claims
    client_id = config.get("client_id", "")
    issuer = config.get("issuer", "https://blackboard.com")
    try:
        public_key = jwk.construct(signing_key)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            audience=client_id or None,
            issuer=issuer,
            options={"verify_aud": bool(client_id)},
        )
    except JWTError as e:
        try:
            payload = jwt.get_unverified_claims(token)
        except Exception:
            payload = {}
        return False, payload, f"JWT verification failed: {e}"

    # 4. Validate nonce
    if payload.get("nonce") != expected_nonce:
        return False, payload, "Nonce mismatch — possible replay attack"

    # 5. Validate LTI version
    lti_version = payload.get(
        "https://purl.imsglobal.org/spec/lti/claim/version"
    )
    if lti_version and lti_version != "1.3.0":
        return False, payload, f"Unexpected LTI version: {lti_version}"

    return True, payload, ""

# ── State cleanup ─────────────────────────────────────────────────────────────

async def cleanup_expired_states():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        expired = [
            s
            for s, d in pending_states.items()
            if now - d["initiated_at"] > STATE_TTL
        ]
        for s in expired:
            pending_states.pop(s, None)

# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="BB LTI Tester", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://daveyherrera.github.io",
        "http://localhost:8080",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

_pub_pem: bytes = b""
_jwks_response: dict = {}


@app.on_event("startup")
async def startup():
    global config, _pub_pem, _jwks_response
    config = load_config()
    _, _pub_pem = ensure_keys()
    _jwks_response = public_key_to_jwks(_pub_pem)
    asyncio.create_task(cleanup_expired_states())


# ── LTI endpoints ─────────────────────────────────────────────────────────────

@app.get("/oidc-login")
async def oidc_login(request: Request):
    """Step 1: Receive OIDC initiation from Blackboard."""
    p = request.query_params
    login_hint = p.get("login_hint", "")
    lti_message_hint = p.get("lti_message_hint", "")
    target_link_uri = p.get("target_link_uri", "")
    client_id = p.get("client_id") or config.get("client_id", "")

    oidc_auth_url = config.get("oidc_auth_url")
    if not oidc_auth_url:
        return HTMLResponse(
            "<h2>Error: OIDC Auth URL not configured. Open the LTI Tester and go to Settings.</h2>",
            status_code=400,
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    pending_states[state] = {
        "nonce": nonce,
        "initiated_at": time.time(),
        "login_hint": login_hint,
        "lti_message_hint": lti_message_hint,
        "target_link_uri": target_link_uri,
        "client_id": client_id,
    }

    ngrok_url = await get_ngrok_url() or "http://localhost:8080"
    redirect_uri = f"{ngrok_url}/redirect"

    from urllib.parse import urlencode

    params = urlencode(
        {
            "response_type": "id_token",
            "scope": "openid",
            "login_hint": login_hint,
            "lti_message_hint": lti_message_hint,
            "state": state,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "nonce": nonce,
            "response_mode": "form_post",
        }
    )
    return RedirectResponse(url=f"{oidc_auth_url}?{params}", status_code=302)


@app.post("/redirect")
async def lti_redirect(
    request: Request,
    id_token: str = Form(...),
    state: str = Form(...),
):
    """Step 2: Receive id_token POST from Blackboard, validate, store, redirect to SPA."""
    state_data = pending_states.pop(state, None)

    launch_id = str(uuid.uuid4())[:8]
    received_at = time.time()

    if not state_data:
        launch = {
            "id": launch_id,
            "received_at": received_at,
            "valid": False,
            "validation_error": "Unknown or expired state — possible CSRF or replay",
            "header": {},
            "payload": {},
            "raw_token": "[redacted]",
            "state": state,
        }
        launches.insert(0, launch)
        if len(launches) > MAX_LAUNCHES:
            launches.pop()
        return RedirectResponse(
            url=f"{GITHUB_PAGES_URL}/?launch={launch_id}&error=invalid_state",
            status_code=302,
        )

    try:
        header = jwt.get_unverified_header(id_token)
    except Exception:
        header = {}

    is_valid, payload, error = await validate_lti_jwt(id_token, state_data["nonce"])

    launch = {
        "id": launch_id,
        "received_at": received_at,
        "valid": is_valid,
        "validation_error": error if not is_valid else "",
        "header": header,
        "payload": payload,
        "raw_token": id_token if not is_valid else "[stored — fetch by ID]",
        "state_data": {k: v for k, v in state_data.items() if k != "nonce"},
    }
    launches.insert(0, launch)
    if len(launches) > MAX_LAUNCHES:
        launches.pop()

    suffix = "" if is_valid else "&error=validation_failed"
    return RedirectResponse(
        url=f"{GITHUB_PAGES_URL}/?launch={launch_id}{suffix}", status_code=302
    )


@app.get("/jwks")
async def get_jwks():
    """Tool's public JWKS — Blackboard uses this to verify messages the tool signs."""
    return JSONResponse(_jwks_response)


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status():
    ngrok_url = await get_ngrok_url()
    cfg = config
    config_complete = bool(
        cfg.get("client_id") and cfg.get("oidc_auth_url") and cfg.get("jwks_url")
    )
    return {
        "server": "running",
        "ngrok_url": ngrok_url,
        "config_complete": config_complete,
        "pending_states": len(pending_states),
        "launch_count": len(launches),
        "registration_urls": {
            "oidc_login": f"{ngrok_url}/oidc-login" if ngrok_url else None,
            "redirect": f"{ngrok_url}/redirect" if ngrok_url else None,
            "jwks": f"{ngrok_url}/jwks" if ngrok_url else None,
        },
    }


@app.get("/api/launches")
async def api_launches():
    return [
        {k: v for k, v in l.items() if k != "raw_token"}
        for l in launches
    ]


@app.get("/api/launches/{launch_id}")
async def api_launch_detail(launch_id: str):
    launch = next((l for l in launches if l["id"] == launch_id), None)
    if not launch:
        raise HTTPException(status_code=404, detail="Launch not found")
    return launch


@app.delete("/api/launches")
async def api_clear_launches():
    launches.clear()
    return {"ok": True}


@app.get("/api/config")
async def api_get_config():
    return config


@app.post("/api/config")
async def api_save_config(request: Request):
    global config
    body = await request.json()
    allowed = {"client_id", "deployment_id", "oidc_auth_url", "jwks_url", "issuer"}
    config = {**DEFAULT_CONFIG, **{k: v for k, v in body.items() if k in allowed}}
    save_config(config)
    return {"ok": True}


@app.get("/api/ngrok")
async def api_ngrok():
    return {"url": await get_ngrok_url()}


@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": time.time()}


# ── Static files ──────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/static/index.html")
