from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import jwt

from .crypto_utils import (
    KeyRecord,
    gen_rsa_keypair,
    minutes_from_now,
    new_kid,
    now_utc,
    public_numbers_to_jwk,
)


@dataclass
class KeyStore:
    """In-memory keystore with one current key and one expired key."""

    current: KeyRecord
    expired: KeyRecord

    @classmethod
    def bootstrap(cls, current_ttl_minutes: int = 30, expired_minutes_ago: int = 60) -> "KeyStore":
        cur = KeyRecord(
            kid=new_kid(),
            private_key=gen_rsa_keypair(),
            expires_at=minutes_from_now(current_ttl_minutes),
        )
        exp = KeyRecord(
            kid=new_kid(),
            private_key=gen_rsa_keypair(),
            expires_at=minutes_from_now(-expired_minutes_ago),
        )
        return cls(current=cur, expired=exp)

    def unexpired_keys(self) -> List[KeyRecord]:
        return [k for k in [self.current] if k.expires_at > now_utc()]

    def as_jwks(self) -> Dict:
        return {
            "keys": [
                public_numbers_to_jwk(k.private_key.public_key(), k.kid)
                for k in self.unexpired_keys()
            ]
        }

    def build_jwt(
        self, use_expired: bool = False, payload_extra: Optional[Dict] = None
    ) -> Tuple[str, KeyRecord]:
        rec = self.expired if use_expired else self.current
        headers = {"kid": rec.kid, "alg": "RS256", "typ": "JWT"}
        payload = {
            "sub": "fake-user-123",
            "iat": int(now_utc().timestamp()),
            "exp": int(rec.expires_at.timestamp()),  # expired token uses past exp
        }
        if payload_extra:
            payload.update(payload_extra)
        token = jwt.encode(payload, rec.private_key, algorithm="RS256", headers=headers)
        return token, rec