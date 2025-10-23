import base64
import time
from typing import Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ALG = "RS256"


def generate_rsa_private_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def serialize_private_key_pkcs1_pem(priv_key: rsa.RSAPrivateKey) -> bytes:
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key_from_pem(pem: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def public_jwk_from_private_pem(kid: int, pem: bytes) -> Dict:
    priv = load_private_key_from_pem(pem)
    pub = priv.public_key().public_numbers()
    n_int, e_int = pub.n, pub.e
    n_b = n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
    e_b = e_int.to_bytes((e_int.bit_length() + 7) // 8, "big")
    n = base64.urlsafe_b64encode(n_b).rstrip(b"=").decode("ascii")
    e = base64.urlsafe_b64encode(e_b).rstrip(b"=").decode("ascii")
    return {"kty": "RSA", "kid": str(kid), "n": n, "e": e, "alg": ALG, "use": "sig"}


def sign_jwt_with_pem(
    pem: bytes, kid: int, subject: str, expires_in_seconds: int = 3600, extra_claims: Dict = None
) -> str:
    priv = load_private_key_from_pem(pem)
    now = int(time.time())
    payload = {"sub": subject, "iat": now, "exp": now + expires_in_seconds}
    if extra_claims:
        payload.update(extra_claims)
    headers = {"kid": str(kid), "alg": ALG, "typ": "JWT"}
    return jwt.encode(payload, priv, algorithm=ALG, headers=headers)