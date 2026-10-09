import time
import uuid

import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="OAuth 2.0 / OIDC Token Verification Service")

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-hk2qkz3o.apps.exam.local"

# Public key transcribed from the assignment screenshot.
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9igw3yiLAA4HCnpITcbWCSelvbYGuC3EbNy4xFyF5Cbj5DHJMID
EkryOgyd2giIIIB0UBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNLdu6A9cNteNpXc
WyJjG2axVfmq7i6Sukr1J0wYG7xTTAvkPujS14OtsQfO3h5NepzdfXp28oNnzfw
ed+zcLR6BcmNNo/WfJ4xyCLSf0BC0gdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgnIT7GkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class VerifyRequest(BaseModel):
    token: str


@app.middleware("http")
async def add_request_headers(request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    elapsed = max(0.0, time.perf_counter() - start)
    response.headers["X-Process-Time"] = f"{elapsed:.6f}"
    return response


@app.get("/")
def home():
    return {
        "service": "OAuth 2.0 / OIDC Token Verification Service",
        "status": "ok",
    }


@app.post("/verify")
def verify_token(body: VerifyRequest):
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["iss", "aud", "exp"]},
        )
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }
    except (jwt.PyJWTError, ValueError, TypeError):
        return JSONResponse(status_code=401, content={"valid": False})
