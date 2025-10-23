import time

from fastapi.testclient import TestClient

from app.crypto_utils import generate_rsa_private_key, serialize_private_key_pkcs1_pem
from app.db import get_connection, init_db, insert_key
from app.main import app

client = TestClient(app)


def reset_and_seed():
    conn = get_connection()
    init_db(conn)
    now = int(time.time())

    priv1 = generate_rsa_private_key()
    insert_key(conn, serialize_private_key_pkcs1_pem(priv1), now - 60)

    priv2 = generate_rsa_private_key()
    insert_key(conn, serialize_private_key_pkcs1_pem(priv2), now + 3600)

    # Close the DB connection used for seeding to avoid ResourceWarning in tests.
    try:
        conn.close()
    except Exception:
        pass


def test_jwks_has_only_valid_keys():
    reset_and_seed()
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    for k in data["keys"]:
        assert k["kty"] == "RSA"
        assert k["alg"] == "RS256"
        assert "kid" in k and "n" in k and "e" in k


def test_auth_issues_token_with_valid_key_by_default():
    reset_and_seed()
    r = client.post("/auth", auth=("userABC", "password123"))
    assert r.status_code == 200
    data = r.json()
    assert "token" in data and "kid" in data and "expired" in data
    assert data["expired"] is False
    jwks = client.get("/.well-known/jwks.json").json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert data["kid"] in kids


def test_auth_can_use_expired_key_when_requested():
    reset_and_seed()
    r = client.post("/auth?expired=1", auth=("userABC", "password123"))
    assert r.status_code == 200
    data = r.json()
    assert "token" in data and "kid" in data and "expired" in data
    assert data["expired"] is True
    jwks = client.get("/.well-known/jwks.json").json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert data["kid"] not in kids