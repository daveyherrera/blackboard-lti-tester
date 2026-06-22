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
    "token_url": "https://developer.blackboard.com/api/v1/gateway/oauth2/jwttoken",
}

# ── In-memory state ──────────────────────────────────────────────────────────

pending_states: dict[str, dict] = {}
launches: list[dict] = []
jwks_cache: dict = {"keys": None, "fetched_at": 0}
_token_cache: dict = {}  # scope_key -> {access_token, expires_at}
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

# ── LTI Service token ─────────────────────────────────────────────────────────

async def get_lti_service_token(scopes: list) -> str:
    scope_str = " ".join(sorted(scopes))
    cached = _token_cache.get(scope_str)
    if cached and time.time() < cached["expires_at"] - 30:
        return cached["access_token"]

    client_id = config.get("client_id", "")
    token_url = config.get("token_url", "https://developer.blackboard.com/api/v1/gateway/oauth2/jwttoken")
    now = int(time.time())

    assertion_claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": [token_url],
        "iat": now,
        "exp": now + 300,
        "jti": secrets.token_urlsafe(16),
    }
    priv_pem = (KEYS_DIR / "private.pem").read_text()
    assertion = jwt.encode(assertion_claims, priv_pem, algorithm="RS256", headers={"kid": "lti-tester-key-1"})

    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(token_url, data={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "scope": scope_str,
        }, headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
        data = r.json()
        _token_cache[scope_str] = {
            "access_token": data["access_token"],
            "expires_at": time.time() + data.get("expires_in", 3600),
        }
        return data["access_token"]


def get_launch_or_404(launch_id: str) -> dict:
    launch = next((l for l in launches if l["id"] == launch_id), None)
    if not launch:
        raise HTTPException(status_code=404, detail="Launch not found")
    return launch


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
    allowed = {"client_id", "deployment_id", "oidc_auth_url", "jwks_url", "issuer", "token_url"}
    config = {**DEFAULT_CONFIG, **{k: v for k, v in body.items() if k in allowed}}
    save_config(config)
    return {"ok": True}


@app.get("/api/ngrok")
async def api_ngrok():
    return {"url": await get_ngrok_url()}


@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": time.time()}


# ── LTI Advantage endpoints ───────────────────────────────────────────────────

@app.post("/api/ags/lineitems")
async def api_ags_lineitems(request: Request):
    body = await request.json()
    launch_id = body.get("launch_id", "")
    launch = get_launch_or_404(launch_id)
    payload = launch.get("payload", {})
    ags_claim = payload.get("https://purl.imsglobal.org/spec/lti-ags/claim/endpoint", {})
    lineitems_url = body.get("lineitem_url") or ags_claim.get("lineitems")
    if not lineitems_url:
        raise HTTPException(status_code=400, detail="No lineitems URL available in launch payload")
    try:
        token = await get_lti_service_token(["https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly"])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token fetch failed: {e}")
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(lineitems_url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.ims.lis.v2.lineitemcontainer+json",
        })
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return {"lineitems": r.json(), "launch_id": launch_id}


@app.post("/api/ags/create-lineitem")
async def api_ags_create_lineitem(request: Request):
    body = await request.json()
    launch_id = body.get("launch_id", "")
    launch = get_launch_or_404(launch_id)
    payload = launch.get("payload", {})
    ags_claim = payload.get("https://purl.imsglobal.org/spec/lti-ags/claim/endpoint", {})
    lineitems_url = ags_claim.get("lineitems")
    if not lineitems_url:
        raise HTTPException(status_code=400, detail="No lineitems URL in launch payload")
    try:
        token = await get_lti_service_token(["https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token fetch failed: {e}")
    lineitem_body = {
        "label": body.get("label", "Untitled"),
        "scoreMaximum": body.get("scoreMaximum", 100),
    }
    if body.get("resourceId"):
        lineitem_body["resourceId"] = body["resourceId"]
    if body.get("tag"):
        lineitem_body["tag"] = body["tag"]
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(lineitems_url, json=lineitem_body, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.ims.lis.v2.lineitem+json",
        })
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()


@app.post("/api/ags/scores")
async def api_ags_scores(request: Request):
    body = await request.json()
    lineitem_url = body.get("lineitem_url", "")
    if not lineitem_url:
        raise HTTPException(status_code=400, detail="lineitem_url required")
    try:
        token = await get_lti_service_token(["https://purl.imsglobal.org/spec/lti-ags/scope/score"])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token fetch failed: {e}")
    score_payload = {
        "userId": body.get("userId", ""),
        "scoreGiven": body.get("scoreGiven", 0),
        "scoreMaximum": body.get("scoreMaximum", 100),
        "activityProgress": body.get("activityProgress", "Completed"),
        "gradingProgress": body.get("gradingProgress", "FullyGraded"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if body.get("comment"):
        score_payload["comment"] = body["comment"]
    scores_url = lineitem_url.rstrip("/") + "/scores"
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(scores_url, json=score_payload, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.ims.lis.v1.score+json",
        })
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return {"ok": True, "status": r.status_code}


@app.post("/api/ags/results")
async def api_ags_results(request: Request):
    body = await request.json()
    lineitem_url = body.get("lineitem_url", "")
    if not lineitem_url:
        raise HTTPException(status_code=400, detail="lineitem_url required")
    try:
        token = await get_lti_service_token(["https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token fetch failed: {e}")
    results_url = lineitem_url.rstrip("/") + "/results"
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(results_url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.ims.lis.v2.resultcontainer+json",
        })
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return {"results": r.json()}


@app.post("/api/nrps/memberships")
async def api_nrps_memberships(request: Request):
    body = await request.json()
    launch_id = body.get("launch_id", "")
    launch = get_launch_or_404(launch_id)
    payload = launch.get("payload", {})
    nrps_claim = payload.get("https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice", {})
    memberships_url = nrps_claim.get("context_memberships_url")
    if not memberships_url:
        raise HTTPException(status_code=400, detail="No NRPS memberships URL in launch payload")
    try:
        token = await get_lti_service_token(["https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token fetch failed: {e}")
    members = []
    next_url = memberships_url
    async with httpx.AsyncClient(timeout=30.0) as client:
        while next_url and len(members) < 500:
            r = await client.get(next_url, headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.ims.lti-nrps.v2.membershipcontainer+json",
            })
            if not r.is_success:
                raise HTTPException(status_code=r.status_code, detail=r.text)
            data = r.json()
            members.extend(data.get("members", []))
            # Follow pagination
            next_url = None
            link_header = r.headers.get("link", "")
            for part in link_header.split(","):
                part = part.strip()
                if 'rel="next"' in part:
                    url_part = part.split(";")[0].strip()
                    if url_part.startswith("<") and url_part.endswith(">"):
                        next_url = url_part[1:-1]
                    break
    return {"members": members, "count": len(members)}


@app.post("/api/deep-link/response")
async def api_deep_link_response(request: Request):
    body = await request.json()
    launch_id = body.get("launch_id", "")
    launch = get_launch_or_404(launch_id)
    payload = launch.get("payload", {})
    dl_settings = payload.get("https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings", {})
    return_url = dl_settings.get("deep_link_return_url")
    if not return_url:
        raise HTTPException(status_code=400, detail="No deep_link_return_url in launch payload")
    dl_data = dl_settings.get("data")
    content_items = body.get("content_items", [])
    now = int(time.time())
    claims = {
        "iss": config.get("client_id"),
        "aud": config.get("issuer", "https://blackboard.com"),
        "iat": now,
        "exp": now + 600,
        "nonce": secrets.token_urlsafe(16),
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingResponse",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": config.get("deployment_id", ""),
        "https://purl.imsglobal.org/spec/lti-dl/claim/content_items": content_items,
    }
    if dl_data:
        claims["https://purl.imsglobal.org/spec/lti-dl/claim/data"] = dl_data
    priv_pem = (KEYS_DIR / "private.pem").read_text()
    signed_token = jwt.encode(claims, priv_pem, algorithm="RS256", headers={"kid": "lti-tester-key-1"})
    return {"jwt": signed_token, "deep_link_return_url": return_url}


@app.get("/api/ags/scopes/{launch_id}")
async def api_ags_scopes(launch_id: str):
    launch = get_launch_or_404(launch_id)
    payload = launch.get("payload", {})
    ags_claim = payload.get("https://purl.imsglobal.org/spec/lti-ags/claim/endpoint", {})
    return {
        "scopes": ags_claim.get("scope", []),
        "lineitems": ags_claim.get("lineitems"),
        "lineitem": ags_claim.get("lineitem"),
    }


# ── Static files ──────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/static/index.html")
