```python
import os
import time
import uuid

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-hk2qkz3o.apps.exam.local"
ALGORITHM = "RS256"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/verify")
async def verify_token(request: Request):
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    try:
        body = await request.json()
        token = body.get("token") if isinstance(body, dict) else None

        if not isinstance(token, str) or not token:
            raise ValueError("Missing token")

        jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )

        valid = True

    except Exception:
        valid = False

    response = JSONResponse({"valid": valid}, status_code=200 if valid else 401)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = str(time.perf_counter() - start)
    return response
```
