import os, time, uuid, json, base64, logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx, jwt
from cryptography.hazmat.primitives import serialization

# ---------- Logging setup (add-only) ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("openemr_s2s_jwt_proxy")

OEMR_BASE = os.getenv("OEMR_BASE", "https://emr.docfico.com").rstrip("/")
SITE      = os.getenv("SITE", "default")
TOKEN_URL = os.getenv("TOKEN_URL", f"{OEMR_BASE}/oauth2/{SITE}/token")
FHIR_BASE = os.getenv("FHIR_BASE", f"{OEMR_BASE}/apis/{SITE}/fhir").rstrip("/")
CLIENT_ID = os.getenv("CLIENT_ID", "")
# For JWT auth:
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", ".keys/private_key.pem")
JWKS_PATH        = os.getenv("JWKS_PATH", ".keys/jwks.json")
KID              = os.getenv("KID", "")  # set to value printed by make_jwks.py
SCOPE            = os.getenv("SCOPE", "system/Patient.read")

if not CLIENT_ID:
    logger.warning("CLIENT_ID not set; set CLIENT_ID env variable")
else:
    logger.info("Config: site=%s, fhir_base=%s, token_url=%s, client_id=%s..., scope=%s",
                SITE, FHIR_BASE, TOKEN_URL, CLIENT_ID[:8], SCOPE)

# cache
_token: Dict[str, Any] = {"access_token": None, "exp": 0}

app = FastAPI(title="OpenEMR S2S via JWT", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ---------- Request logging middleware (add-only) ----------
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

@app.get("/health")
def health():
    logger.debug("Health check")
    return {"ok": True, "site": SITE, "fhir_base": FHIR_BASE}

@app.get("/.well-known/jwks.json")
def jwks():
    logger.info("JWKS requested at %s", JWKS_PATH)
    if not os.path.exists(JWKS_PATH):
        logger.error("JWKS file not found: %s", JWKS_PATH)
        raise HTTPException(404, "jwks.json not found")
    try:
        data = json.load(open(JWKS_PATH))
        logger.debug("JWKS served with %d key(s)", len(data.get(".keys", [])))
        return JSONResponse(data)
    except Exception as e:
        logger.exception("Failed to read JWKS: %s", e)
        raise HTTPException(500, "jwks.json read error")

def build_client_assertion() -> str:
    """ RS384 JWT per SMART Backend Services:
        iss=sub=client_id, aud=TOKEN_URL, jti unique, short exp. """
    logger.debug("Building client assertion (kid=%s, alg=RS384, aud=%s)", KID, TOKEN_URL)
    try:
        priv_pem = open(PRIVATE_KEY_PATH, "rb").read()
    except Exception as e:
        logger.exception("Unable to read private key at %s: %s", PRIVATE_KEY_PATH, e)
        raise
    now = int(time.time())
    payload = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": TOKEN_URL,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300
    }
    headers = {"kid": KID, "typ": "JWT", "alg": "RS384"}
    try:
        assertion = jwt.encode(payload, priv_pem, algorithm="RS384", headers=headers)
        logger.debug("Client assertion built (iss=%s..., iat=%s, exp=%s)", (CLIENT_ID or "")[:8], payload["iat"], payload["exp"])
        return assertion
    except Exception as e:
        logger.exception("Failed to sign client assertion: %s", e)
        raise

async def fetch_token_jwt() -> Dict[str, Any]:
    logger.info("Requesting system token via JWT client assertion → %s", TOKEN_URL)
    assertion = build_client_assertion()
    form = {
        "grant_type": "client_credentials",
        "scope": SCOPE,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
        "client_id": CLIENT_ID  # OpenEMR expects it in many builds
    }
    async with httpx.AsyncClient(timeout=30.0) as cx:
        try:
            r = await cx.post(TOKEN_URL, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
        except Exception as e:
            logger.exception("HTTP error calling token endpoint: %s", e)
            raise

    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}

    if r.status_code != 200:
        logger.error("Token endpoint returned %s: %s", r.status_code, body)
        raise HTTPException(r.status_code, {"token_error": body})

    _token["access_token"] = body.get("access_token")
    _token["exp"] = int(time.time()) + int(body.get("expires_in", 300)) - 5
    logger.info("System token acquired; expires_at=%s (unix)", _token["exp"])
    return body

def expired() -> bool:
    exp = _token.get("exp", 0)
    if not _token.get("access_token"):
        return True
    return time.time() >= exp

@app.post("/oauth/token")
async def token(force: Optional[bool] = False):
    logger.info("Token endpoint called (force=%s, expired=%s)", force, expired())
    if force or expired():
        t = await fetch_token_jwt()
        return t
    logger.debug("Returning cached token (exp=%s)", _token["exp"])
    return {"access_token": _token["access_token"], "expires_at": _token["exp"]}

async def forward(method: str, path: str, req: Request) -> Response:
    if expired():
        logger.info("Cached token expired; refreshing before forwarding")
        await fetch_token_jwt()

    upstream = f"{FHIR_BASE}/{path}".replace("//","/").replace("https:/","https://")
    if req.url.query:
        upstream += "?" + req.url.query
    logger.info("Proxying %s %s → %s", method, req.url.path, upstream)

    try:
        body = await req.body()
        body_len = len(body) if body else 0
    except Exception as e:
        logger.exception("Failed reading request body: %s", e)
        body = None
        body_len = 0

    headers = dict(req.headers)
    # 🔧 strip any client-sent Authorization/Cookie to avoid leaking or overriding
    headers.pop('authorization', None)
    headers.pop('Authorization', None)
    headers.pop('cookie', None)
    headers.pop('Cookie', None)

    # attach our system token only
    headers["Authorization"] = f"Bearer {_token['access_token']}"
    # be explicit for FHIR
    headers["Accept"] = "application/fhir+json"
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=None) as cx:
        try:
            start = time.time()
            resp = await cx.request(method, upstream, content=body, headers=headers)
            dur = (time.time() - start) * 1000.0
            logger.info("Upstream %s %s → %s in %.1f ms", method, upstream, resp.status_code, dur)
        except Exception as e:
            logger.exception("HTTP error forwarding to FHIR upstream: %s", e)
            raise

    try:
        content = await resp.aread()
    except Exception as e:
        logger.exception("Failed to read upstream response body: %s", e)
        content = b""

    passthru = {k: v for k, v in resp.headers.items() if k.lower() not in {"content-encoding","transfer-encoding","connection"}}
    return Response(content, status_code=resp.status_code, headers=passthru, media_type=resp.headers.get("content-type"))

@app.api_route("/fhir/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE"])
async def fhir_proxy(path: str, request: Request):
    return await forward(request.method, path, request)
