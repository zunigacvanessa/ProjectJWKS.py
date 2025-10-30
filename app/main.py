import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from app.crypto_utils import (
    generate_rsa_private_key,
    public_jwk_from_private_pem,
    serialize_private_key_pkcs1_pem,
    sign_jwt_with_pem,
)
from app.db import (
    count_valid_and_expired,
    get_all_valid_keys,
    get_connection,
    get_one_key,
    init_db,
    insert_key,
)

app = FastAPI(title="JWKS Server with SQLite")
security = HTTPBasic()


@app.on_event("startup")
def on_startup():
    conn = get_connection()
    init_db(conn)
    counts = count_valid_and_expired(conn)
    now = int(time.time())

    if counts["expired"] < 1:
        priv = generate_rsa_private_key()
        pem = serialize_private_key_pkcs1_pem(priv)
        insert_key(conn, pem, now - 60)

    if counts["valid"] < 1:
        priv = generate_rsa_private_key()
        pem = serialize_private_key_pkcs1_pem(priv)
        insert_key(conn, pem, now + 3600)


class AuthJSON(BaseModel):
    username: str
    password: str


def _basic_or_json_user(creds: Optional[HTTPBasicCredentials], body: Optional[AuthJSON]) -> str:
    if creds and creds.username:
        return creds.username
    if body and body.username:
        return body.username
    return "userABC"


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/auth")
async def issue_token(
    request: Request,
    expired: Optional[int] = None,
    creds: HTTPBasicCredentials = Depends(security),
    body: Optional[AuthJSON] = None,
):
    want_expired = bool(expired)
    conn = get_connection()
    row = get_one_key(conn, want_expired=want_expired)
    if not row:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No matching key in DB",
        )
    kid, key_pem, exp_ts = row
    username = _basic_or_json_user(creds, body)
    token = sign_jwt_with_pem(pem=key_pem, kid=kid, subject=username, expires_in_seconds=3600)
    return {"token": token, "kid": str(kid), "key_exp": exp_ts}


@app.get("/.well-known/jwks.json")
async def jwks():
    conn = get_connection()
    rows = get_all_valid_keys(conn)
    keys = [public_jwk_from_private_pem(kid=row[0], pem=row[1]) for row in rows]
    return JSONResponse(content={"keys": keys}, headers={"Cache-Control": "public, max-age=300"})
