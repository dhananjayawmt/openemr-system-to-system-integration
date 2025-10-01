import os, time, uuid, json, logging
from typing import Dict, Any, Optional, Tuple
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx, jwt

# =========================
# Logging
# =========================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("openemr_s2s_proxy")

# =========================
# Config
# =========================
OEMR_BASE = os.getenv("OEMR_BASE", "https://emr.docfico.com").rstrip("/")
SITE      = os.getenv("SITE", "default")

TOKEN_URL = os.getenv("TOKEN_URL", f"{OEMR_BASE}/oauth2/{SITE}/token")
REG_URL   = os.getenv("REG_URL",   f"{OEMR_BASE}/oauth2/{SITE}/registration")

FHIR_BASE = os.getenv("FHIR_BASE", f"{OEMR_BASE}/apis/{SITE}/fhir").rstrip("/")
REST_BASE = os.getenv("REST_BASE", f"{OEMR_BASE}/apis/{SITE}/api").rstrip("/")

# Client + keys
CLIENT_ID         = os.getenv("CLIENT_ID", "")
CLIENT_NAME       = os.getenv("CLIENT_NAME", "openemr-s2s-proxy (std+fhir)")
PRIVATE_KEY_PATH  = os.getenv("PRIVATE_KEY_PATH", ".keys/private_key.pem")
JWKS_PATH         = os.getenv("JWKS_PATH", ".keys/jwks.json")
KID               = os.getenv("KID", "")

# Scopes
FHIR_SCOPE = os.getenv("FHIR_SCOPE", "system/Patient.read")
# Keep REST scopes simple; most installs enforce site + api:oemr. Add more if your server requires.
REST_SCOPE = os.getenv("REST_SCOPE", f"site:{SITE} api:oemr")

# Grants
# For Standard API writes, OpenEMR typically needs a user-context token (password grant).
REST_GRANT = os.getenv("REST_GRANT", "password").lower()  # 'password' or 'client_credentials'

# Service user for password grant
OEMR_USERNAME  = os.getenv("OEMR_USERNAME", "")
OEMR_PASSWORD  = os.getenv("OEMR_PASSWORD", "")
OEMR_USER_ROLE = os.getenv("OEMR_USER_ROLE", "users")  # 'users' for staff/provider; 'patient' for portal logins

# Registration scopes (DCR). These are the scopes your client is allowed to request.
REGISTER_SCOPES  = os.getenv(
    "REGISTER_SCOPES",
    f"site:{SITE} api:oemr api:fhir openid offline_access"
)

if not CLIENT_ID:
    logger.warning("CLIENT_ID not set; you can create+activate via POST /oauth/register and then set CLIENT_ID in env (or use /config/client).")

logger.info(
    "Config: site=%s\nfhir_base=%s\nrest_base=%s\ntoken_url=%s\nclient_id=%s",
    SITE, FHIR_BASE, REST_BASE, TOKEN_URL, CLIENT_ID or "<unset>"
)

# Active client_id in-memory (can be updated via /oauth/register?activate=true or /config/client)
_active_client_id: str = CLIENT_ID

# Token cache: key by (scope, grant, username, user_role)
_tokens: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

# =========================
# FastAPI
# =========================
app = FastAPI(title="OpenEMR S2S Proxy", version="1.4.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# =========================
# Models
# =========================
class RegisterIn(BaseModel):
    client_name: Optional[str] = None
    scopes: Optional[str] = None
    activate: Optional[bool] = False  # set the returned client_id active in-memory

class SetClientIn(BaseModel):
    client_id: str

# =========================
# Middleware (logging)
# =========================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    path_qs = request.url.path + (("?" + request.url.query) if request.url.query else "")
    logger.info("→ %s %s", request.method, path_qs)
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled exception during %s %s", request.method, path_qs)
        raise
    ms = (time.time() - start) * 1000.0
    logger.info("← %s %s %s in %.1f ms", request.method, path_qs, response.status_code, ms)
    return response

# =========================
# Helpers
# =========================
def _parse_token_json(r: httpx.Response) -> Dict[str, Any]:
    """
    Robustly parse token JSON even if server prepends HTML notices.
    """
    ct = (r.headers.get("content-type") or "").lower()
    if "application/json" in ct:
        try:
            return r.json()
        except Exception:
            pass
    txt = r.text or ""
    start, end = txt.find("{"), txt.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = txt[start:end+1]
        try:
            return json.loads(candidate.lstrip("\ufeff").strip())
        except Exception:
            pass
    try:
        return json.loads((txt or "").lstrip("\ufeff").strip())
    except Exception:
        raise HTTPException(
            status_code=502 if r.status_code == 200 else r.status_code,
            detail={
                "token_error": "invalid_json_from_token_endpoint",
                "status": r.status_code,
                "content_type": ct,
                "sample": (txt[:400] if txt else "<empty>")
            }
        )

def _decode_jwt_nosig(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception:
        return {}

def _log_granted(body: Dict[str, Any]) -> None:
    at = body.get("access_token") or ""
    claims = _decode_jwt_nosig(at) if at else {}
    scopes = claims.get("scopes") or claims.get("scope") or body.get("scope")
    logger.info("Token ok (sub=%s, aud=%s, scopes=%s)", claims.get("sub"), claims.get("aud"), scopes)

def build_client_assertion() -> str:
    """
    SMART Backend Services JWT: iss=sub=_active_client_id, aud=TOKEN_URL
    """
    global _active_client_id
    now = int(time.time())
    payload = {
        "iss": _active_client_id,
        "sub": _active_client_id,
        "aud": TOKEN_URL,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300
    }
    headers = {"kid": KID, "typ": "JWT", "alg": "RS384"}
    try:
        priv_pem = open(PRIVATE_KEY_PATH, "rb").read()
    except Exception:
        logger.exception("Unable to read private key at %s", PRIVATE_KEY_PATH)
        raise
    return jwt.encode(payload, priv_pem, algorithm="RS384", headers=headers)

async def fetch_token(scope: str, grant: str,
                      username: Optional[str] = None,
                      password: Optional[str] = None,
                      user_role: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetch token using private_key_jwt client auth.
    - FHIR: grant=client_credentials
    - Standard API: grant=password (recommended) with user_role=users
    """
    logger.info("Fetching token grant=%s scope=%s (client_id=%s)", grant, scope, _active_client_id or "<unset>")
    form = {
        "grant_type": grant,
        "scope": scope,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": build_client_assertion(),
        "client_id": _active_client_id,
    }
    if grant == "password":
        if not (username and password):
            raise HTTPException(500, "REST_GRANT=password but OEMR_USERNAME/OEMR_PASSWORD not set")
        form.update({
            "username": username,
            "password": password,
            "user_role": (user_role or "users")
        })

    async with httpx.AsyncClient(timeout=30.0) as cx:
        r = await cx.post(
            TOKEN_URL,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        )

    if r.status_code != 200:
        try:
            err = r.json()
        except Exception:
            err = {"raw": (r.text[:400] if r.text else "")}
        logger.error("Token endpoint error %s: %s", r.status_code, err)
        raise HTTPException(r.status_code, {"token_error": err})

    body = _parse_token_json(r)
    _log_granted(body)

    key = (scope, grant, username or "", user_role or "")
    _tokens[key] = {
        "access_token": body.get("access_token"),
        "exp": int(time.time()) + int(body.get("expires_in", 300)) - 5
    }
    return body

def _expired(scope: str, grant: str, username: Optional[str], user_role: Optional[str]) -> bool:
    t = _tokens.get((scope, grant, username or "", user_role or ""))
    return (not t) or (not t.get("access_token")) or (time.time() >= t.get("exp", 0))

async def ensure_token(scope: str, grant: str,
                       username: Optional[str] = None,
                       password: Optional[str] = None,
                       user_role: Optional[str] = None) -> str:
    key = (scope, grant, username or "", user_role or "")
    if _expired(scope, grant, username, user_role):
        await fetch_token(scope, grant, username, password, user_role)
    return _tokens[key]["access_token"]

async def forward_generic(method: str, base: str, accept: str, scope: str,
                          path: str, req: Request, grant: str,
                          username: Optional[str] = None,
                          password: Optional[str] = None,
                          user_role: Optional[str] = None) -> Response:
    token = await ensure_token(scope, grant, username, password, user_role)

    upstream = f"{base}/{path}".replace("//","/").replace("https:/","https://")
    if req.url.query:
        upstream += "?" + req.url.query

    try:
        body = await req.body()
    except Exception:
        body = None

    headers = dict(req.headers)
    # strip headers that shouldn't pass through
    for h in ("authorization","Authorization","cookie","Cookie","host","Host","content-length","Content-Length"):
        headers.pop(h, None)
    headers["Authorization"] = f"Bearer {token}"
    headers["Accept"] = accept
    # Do NOT force Content-Type here; let client/body set it.

    async with httpx.AsyncClient(timeout=None) as cx:
        resp = await cx.request(method, upstream, content=body, headers=headers)

    try:
        content = await resp.aread()
    except Exception:
        content = b""

    passthru = {k: v for k, v in resp.headers.items()
                if k.lower() not in {"content-encoding","transfer-encoding","connection"}}
    return Response(content, status_code=resp.status_code, headers=passthru,
                    media_type=resp.headers.get("content-type"))

# =========================
# Routes
# =========================
@app.get("/health")
def health():
    return {
        "ok": True,
        "site": SITE,
        "fhir_base": FHIR_BASE,
        "rest_base": REST_BASE,
        "token_url": TOKEN_URL,
        "reg_url": REG_URL,
        "active_client_id": _active_client_id or "<unset>",
        "rest_grant": REST_GRANT,
    }

@app.get("/.well-known/jwks.json")
def jwks():
    if not os.path.exists(JWKS_PATH):
        raise HTTPException(404, "jwks.json not found")
    return JSONResponse(json.load(open(JWKS_PATH)))

# ---- Dynamic Client Registration (server calls OpenEMR; Postman calls this) ----
@app.post("/oauth/register")
async def register_client():
    if not os.path.exists(JWKS_PATH):
        raise HTTPException(400, f"JWKS not found at {JWKS_PATH}")
    try:
        jwks = json.load(open(JWKS_PATH))
        if not isinstance(jwks, dict) or not jwks.get("keys"):
            raise ValueError("Invalid JWKS")
    except Exception:
        logger.exception("Failed to read/parse JWKS at %s", JWKS_PATH)
        raise HTTPException(400, "Invalid JWKS file")

    payload = {
        "client_name": 'Test API Client',
        "application_type": "private",
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["client_credentials", "password", "refresh_token"],
        "response_types": ["token"],
        "redirect_uris": ["https://localhost:8000"],
        "scope": REST_SCOPE,
        "jwks": jwks
    }

    async with httpx.AsyncClient(timeout=30.0) as cx:
        r = await cx.post(REG_URL, json=payload, headers={"Content-Type": "application/json", "Accept": "application/json"})

    try:
        data = r.json()
    except Exception:
        data = {"raw": (r.text[:400] if r.text else "")}

    if r.status_code not in (200, 201):
        logger.error("Registration failed (%s): %s", r.status_code, data)
        raise HTTPException(r.status_code, {"registration_error": data})

    client_id = data.get("client_id")

    if client_id:
        global _active_client_id
        _active_client_id = client_id
        _tokens.clear()
        data["_activated"] = True
        logger.info("Activated new client_id in-memory: %s", _active_client_id)

    return JSONResponse(data, status_code=r.status_code)

# ---- Switch active client_id at runtime (no restart) ----
@app.post("/config/client")
def set_active_client(cfg: SetClientIn):
    if not cfg.client_id.strip():
        raise HTTPException(400, "client_id cannot be empty")
    global _active_client_id
    _active_client_id = cfg.client_id.strip()
    _tokens.clear()
    logger.info("Active client_id set to %s (token cache cleared)", _active_client_id)
    return {"active_client_id": _active_client_id}

# ---- Token priming endpoint (Postman can call this) ----
@app.post("/oauth/token")
async def token(force: Optional[bool] = False, scope: Optional[str] = None, kind: Optional[str] = None):
    """
    kind=fhir -> client_credentials, scope=FHIR_SCOPE by default
    kind=rest -> password (or REST_GRANT), scope=REST_SCOPE by default
    """
    if kind not in ("fhir", "rest", None):
        raise HTTPException(400, "kind must be one of: fhir, rest")

    if kind == "rest":
        use_scope = (scope or REST_SCOPE).strip()
        grant = REST_GRANT
        if grant == "password":
            key = (use_scope, grant, OEMR_USERNAME or "", OEMR_USER_ROLE or "")
            if force or _expired(use_scope, grant, OEMR_USERNAME, OEMR_USER_ROLE):
                return await fetch_token(use_scope, grant, OEMR_USERNAME, OEMR_PASSWORD, OEMR_USER_ROLE)
            t = _tokens[key]
            return {"access_token": t["access_token"], "expires_at": t["exp"]}
        else:
            # client_credentials (not recommended for Standard API writes)
            key = (use_scope, "client_credentials", "", "")
            if force or _expired(use_scope, "client_credentials", "", ""):
                return await fetch_token(use_scope, "client_credentials")
            t = _tokens[key]
            return {"access_token": t["access_token"], "expires_at": t["exp"]}

    # default/fhir
    use_scope = (scope or FHIR_SCOPE).strip()
    key = (use_scope, "client_credentials", "", "")
    if force or _expired(use_scope, "client_credentials", "", ""):
        return await fetch_token(use_scope, "client_credentials")
    t = _tokens[key]
    return {"access_token": t["access_token"], "expires_at": t["exp"]}

# ---- Proxies ----
@app.api_route("/fhir/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE"])
async def fhir_proxy(path: str, request: Request):
    return await forward_generic(
        request.method, FHIR_BASE, "application/fhir+json",
        FHIR_SCOPE, path, request,
        grant="client_credentials"
    )

@app.api_route("/rest/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE"])
async def rest_proxy(path: str, request: Request):
    # Standard API: use password grant so token maps to a real user (add role)
    return await forward_generic(
        request.method, REST_BASE, "application/json",
        REST_SCOPE, path, request,
        grant=REST_GRANT, username=OEMR_USERNAME, password=OEMR_PASSWORD, user_role=OEMR_USER_ROLE
    )
