# OpenEMR System-to-System (JWT Client Assertion) FastAPI Proxy

A tiny **FastAPI** service that lets you call **OpenEMR FHIR** APIs using **system-to-system** auth (SMART Backend Services style).  
It signs a **JWT client assertion** with your private key, fetches a **system access token**, and **proxies** `/fhir/*` requests with the token attached.

> ✅ Works great with **Postman**.  
> 🔐 Uses **JWKS** (public key) at registration; you keep the **private key** locally.

---

## What you get

- **Server code (with logs):** [main.py](sandbox:/mnt/data/main_with_logs.py)
- **Postman Environment:** [OpenEMR_S2S_JWT_PythonProxy.postman_environment.json](sandbox:/mnt/data/OpenEMR_S2S_JWT_PythonProxy.postman_environment.json)
- **Postman Collection:** [OpenEMR_S2S_JWT_PythonProxy.postman_collection.json](sandbox:/mnt/data/OpenEMR_S2S_JWT_PythonProxy.postman_collection.json)

> If you prefer a minimal file name, you can also rename/copy `main_with_logs.py` to `main.py` before running uvicorn.

---

## Prerequisites

- Python **3.10+**
- An OpenEMR 7.x instance with OAuth2/FHIR enabled (site: `default`)
- Admin access to OpenEMR to **enable API Clients** and, if using `system/*` scopes, **enable FHIR System Scopes**

---

## 1) Create a venv & install deps

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

---

## 2) Generate keys & JWKS (and capture the **kid**)

```bash
mkdir -p .keys
# Private RSA key (2048)
openssl genrsa -out .keys/private_key.pem 2048
# Public key
openssl rsa -in .keys/private_key.pem -pubout -out .keys/public_key.pem
```

Create `make_jwks.py` to produce `keys/jwks.json` and print a stable **kid**:

```python
# make_jwks.py
import base64, json, hashlib
from cryptography.hazmat.primitives import serialization


def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")


pub = serialization.load_pem_public_key(open(".keys/public_key.pem", "rb").read())
nums = pub.public_numbers()
n = b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, 'big'))
e = b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, 'big'))

kid = hashlib.sha256((n + e).encode()).hexdigest()[:32]
jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS384", "kid": kid, "n": n, "e": e}]}
open(".keys/jwks.json", "w").write(json.dumps(jwks, indent=2))
print("kid:", kid)
```

Run it:

```bash
python make_jwks.py
# -> writes .keys/jwks.json
# -> prints: kid: <YOUR_KID>
```

Save the printed **kid**; you’ll put it in your server’s env.

---

## 3) Configure the server (env vars)

Create `.env`:

```
# OpenEMR instance
OEMR_BASE=https://emr.docfico.com
SITE=default

# Your registered client
CLIENT_ID=<client_id_from_registration>

# Key material / JWKS
PRIVATE_KEY_PATH=keys/private_key.pem
JWKS_PATH=keys/jwks.json
KID=<kid_printed_by_make_jwks.py>

# Scopes
SCOPE=system/Patient.read system/Observation.read

# Optional overrides
# TOKEN_URL=https://emr.docfico.com/oauth2/default/token
# FHIR_BASE=https://emr.docfico.com/apis/default/fhir

# Logging
LOG_LEVEL=INFO
```

---

## 4) Run the server

```bash
uvicorn main:app --reload --port 8000 --env-file .env
```

Optional HTTPS (if you have local certs):
```bash
uvicorn main:app --port 8443 \
  --ssl-keyfile certs/localhost-key.pem \
  --ssl-certfile certs/localhost.pem \
  --env-file env
```

Health check:
```bash
curl http://localhost:8000/health
```

---

## 5) Endpoints (provided by the server)

- `GET /health` — sanity check (site, fhir_base)
- `GET /.well-known/jwks.json` — serves your JWKS (useful if you switch to `jwks_uri`)
- `POST /oauth/token[?force=true]` — gets/caches a system token using **JWT client assertion**
- `ANY /fhir/{path}` — proxies to OpenEMR FHIR (adds `Authorization: Bearer <system_token>`)

> **Important tip (proxying)**  
> Clients (e.g., Postman) **should not** send their own `Authorization` header to the proxy; the proxy attaches its own system token. If you must keep it enabled in Postman, adjust the server to **strip incoming `Authorization`** before forwarding (see Troubleshooting).

---

## 6) Quick test with curl

1) Get a token (proxy will also auto-refresh when needed):
```bash
curl -X POST "http://localhost:8000/oauth/token?force=true"
```

2) CapabilityStatement via proxy:
```bash
curl -H "Accept: application/fhir+json" "http://localhost:8000/fhir/metadata"
```

3) Patients via proxy:
```bash
curl -H "Accept: application/fhir+json" "http://localhost:8000/fhir/Patient?_count=5"
```

Direct (bypassing proxy) to validate token itself (paste your token):
```bash
curl -H "Authorization: Bearer <ACCESS_TOKEN>" \
     -H "Accept: application/fhir+json" \
  "https://emr.docfico.com/apis/default/fhir/Patient?_count=5"
```

---

## 7) Test with Postman

1) Import both files:
   - **Environment:** [OpenEMR_S2S_JWT_PythonProxy.postman_environment.json](sandbox:/mnt/data/OpenEMR_S2S_JWT_PythonProxy.postman_environment.json)  
   - **Collection:** [OpenEMR_S2S_JWT_PythonProxy.postman_collection.json](sandbox:/mnt/data/OpenEMR_S2S_JWT_PythonProxy.postman_collection.json)

2) Select the environment, then run:
   - **Health**
   - **Get/Refresh System Token**
   - **FHIR – CapabilityStatement**
   - **FHIR – Patient Search**
   - **FHIR – Create Patient** (sample body included)

> If you see “JWT string must have two dots”: set FHIR requests to **No Auth** (no Authorization header). The proxy injects the correct Bearer token.

---

## 8) Troubleshooting

- **“JWT string must have two dots” (401 from FHIR)**  
  - Cause: Upstream saw a bad/empty `Authorization` header (often due to forwarding the client’s header).  
  - Fix (client): In Postman, set FHIR requests to **No Auth**.  
  - Fix (server): Strip incoming `Authorization` before setting the proxy’s token:
    ```python
    headers = dict(req.headers)
    headers.pop('authorization', None)
    headers.pop('Authorization', None)
    headers["Authorization"] = f"Bearer {_token['access_token']}"
    headers["Accept"] = "application/fhir+json"
    ```

- **`invalid_client` at token endpoint**  
  - Ensure the client is **Enabled** in OpenEMR UI and your **kid/alg=RS384** matches the registered key.

- **`invalid_scope`**  
  - Turn on **FHIR System Scopes** in OpenEMR and include allowed scopes for your client (`system/*`).

- **`aud`/`alg` mismatches**  
  - The client assertion must use **RS384** and `aud` must be the **token endpoint** URL.

Enable verbose logs:
```bash
export LOG_LEVEL=DEBUG
uvicorn main:app --reload --port 8000 --env-file env
```

---

## 9) Security notes

- Keep `keys/private_key.pem` out of version control.
- Prefer `jwks_uri` for production (rotations), hosted over HTTPS.
- Lock down your proxy (e.g., IP allow-list, auth) if exposing publicly.
- For write access, request minimal necessary scopes (e.g., `system/Observation.write`) and confirm OpenEMR policy allows writes.

---

## 12) Project layout (suggested)

```
openemr-system-to-system-integration/
├─ main.py
├─ make_jwks.py
├─ keys/
│  ├─ private_key.pem
│  ├─ public_key.pem
│  └─ jwks.json
├─ .env
├─ README.md
├─ postman/
│  ├─ OpenEMR_S2S_JWT_PythonProxy.postman_environment.json
│  └─ OpenEMR_S2S_JWT_PythonProxy.postman_collection.json
└─ requirements.txt
```
