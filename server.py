import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Optional
from datetime import datetime

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
import base64

BASE_DIR = Path(__file__).parent
KEYS_DIR = BASE_DIR / "keys"
SETTINGS_FILE = BASE_DIR / "settings.json"
STATIC_DIR = BASE_DIR / "static"

KEYS_DIR.mkdir(exist_ok=True)

# Key management
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (KEYS_DIR / "private.pem").write_bytes(private_pem)
    (KEYS_DIR / "public.pem").write_bytes(public_pem)
    return private_key

def load_or_generate_keys():
    if not (KEYS_DIR / "private.pem").exists():
        return generate_keys()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    pem = (KEYS_DIR / "private.pem").read_bytes()
    return load_pem_private_key(pem, password=None, backend=default_backend())

private_key = load_or_generate_keys()
public_key = private_key.public_key()

def public_key_to_jwks():
    pub_numbers = public_key.public_numbers()

    def int_to_base64url(n):
        byte_length = (n.bit_length() + 7) // 8
        b = n.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "lti-tester-key-1",
            "n": int_to_base64url(pub_numbers.n),
            "e": int_to_base64url(pub_numbers.e),
        }]
    }

# Config
def load_config():
    if SETTINGS_FILE.exists():
        return json.loads(SETTINGS_FILE.read_text())
    return {
        "client_id": "",
        "deployment_id": "",
        "oidc_auth_url": "https://developer.blackboard.com/api/v1/gateway/oidcauth",
        "jwks_url": "https://developer.blackboard.com/api/v1/management/applications/keys",
        "issuer": "https://blackboard.com"
    }

def save_config(data: dict):
    SETTINGS_FILE.write_text(json.dumps(data, indent=2))

config = load_config()

# In-memory state
pending_states: dict = {}
launches: list = []

app = FastAPI(title="BB LTI Tester")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_ngrok_url():
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get("http://localhost:4040/api/tunnels")
            data = resp.json()
            tunnels = data.get("tunnels", [])
            for t in tunnels:
                if t.get("proto") == "https":
                    return t["public_url"]
    except Exception:
        pass
    return None

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

@app.get("/oidc-login")
async def oidc_login(
    login_hint: str = "",
    lti_message_hint: str = "",
    client_id: str = "",
    lti_deployment_id: str = "",
    target_link_uri: str = ""
):
    global config
    config = load_config()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    pending_states[state] = {
        "nonce": nonce,
        "timestamp": time.time(),
        "login_hint": login_hint,
        "lti_message_hint": lti_message_hint,
        "initiated_at": datetime.utcnow().isoformat()
    }

    ngrok_url = await get_ngrok_url()
    base_url = ngrok_url if ngrok_url else "http://localhost:8080"

    used_client_id = client_id or config.get("client_id", "")
    auth_url = config.get("oidc_auth_url", "")

    redirect_url = (
        f"{auth_url}"
        f"?response_type=id_token"
        f"&scope=openid"
        f"&login_hint={login_hint}"
        f"&lti_message_hint={lti_message_hint}"
        f"&state={state}"
        f"&redirect_uri={base_url}/redirect"
        f"&client_id={used_client_id}"
        f"&nonce={nonce}"
    )
    return RedirectResponse(url=redirect_url)

@app.post("/redirect")
async def lti_redirect(
    id_token: str = Form(...),
    state: str = Form(...)
):
    global config
    config = load_config()

    if state not in pending_states:
        return HTMLResponse(content="<h1>Error: Unknown state. Launch may have expired.</h1>", status_code=400)

    state_data = pending_states.pop(state)
    launch_id = str(uuid.uuid4())[:8]
    received_at = datetime.utcnow().isoformat()

    launch = {
        "id": launch_id,
        "received_at": received_at,
        "raw_token": id_token,
        "header": {},
        "payload": {},
        "state": state,
        "valid": False,
        "validation_error": None
    }

    try:
        # Decode header without verification
        header = jwt.get_unverified_header(id_token)
        launch["header"] = header
        kid = header.get("kid")
        alg = header.get("alg", "RS256")

        # Fetch JWKS
        jwks_url = config.get("jwks_url", "")
        if not jwks_url:
            raise ValueError("JWKS URL not configured")

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(jwks_url)
            jwks = resp.json()

        # Find matching key
        keys = jwks.get("keys", [])
        matching_key = None
        for k in keys:
            if kid and k.get("kid") == kid:
                matching_key = k
                break
        if not matching_key and keys:
            matching_key = keys[0]
        if not matching_key:
            raise ValueError(f"No matching key found for kid={kid}")

        # Verify JWT
        client_id = config.get("client_id", "")
        issuer = config.get("issuer", "https://blackboard.com")

        payload = jwt.decode(
            id_token,
            matching_key,
            algorithms=[alg],
            audience=client_id,
            issuer=issuer,
            options={"verify_exp": True}
        )

        # Check nonce
        if payload.get("nonce") != state_data["nonce"]:
            raise ValueError("Nonce mismatch")

        launch["payload"] = payload
        launch["valid"] = True

    except Exception as e:
        launch["validation_error"] = str(e)
        # Try to decode payload without verification for debugging
        try:
            payload = jwt.decode(id_token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
            launch["payload"] = payload
        except Exception:
            try:
                parts = id_token.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(padded))
                    launch["payload"] = decoded
            except Exception:
                pass

    # Keep last 50 launches
    launches.insert(0, launch)
    if len(launches) > 50:
        launches.pop()

    return RedirectResponse(url=f"http://localhost:8080/?launch={launch_id}", status_code=303)

@app.get("/jwks")
async def jwks():
    return JSONResponse(content=public_key_to_jwks())

@app.get("/api/status")
async def api_status():
    global config
    config = load_config()
    ngrok_url = await get_ngrok_url()
    config_complete = bool(
        config.get("client_id") and
        config.get("oidc_auth_url") and
        config.get("jwks_url")
    )
    return {
        "server": "running",
        "ngrok_url": ngrok_url,
        "config_complete": config_complete,
        "pending_states": len(pending_states),
        "launch_count": len(launches)
    }

@app.get("/api/launches")
async def api_launches():
    result = []
    for l in launches:
        item = {k: v for k, v in l.items() if k != "raw_token"}
        result.append(item)
    return result

@app.get("/api/launches/{launch_id}")
async def api_launch_detail(launch_id: str):
    for l in launches:
        if l["id"] == launch_id:
            return l
    raise HTTPException(status_code=404, detail="Launch not found")

@app.delete("/api/launches")
async def api_clear_launches():
    launches.clear()
    return {"cleared": True}

@app.get("/api/config")
async def api_get_config():
    global config
    config = load_config()
    return config

@app.post("/api/config")
async def api_save_config(request: Request):
    global config
    data = await request.json()
    # Merge with existing config
    current = load_config()
    current.update(data)
    save_config(current)
    config = current
    return {"saved": True}

@app.get("/api/ngrok")
async def api_ngrok():
    url = await get_ngrok_url()
    return {"url": url}

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
