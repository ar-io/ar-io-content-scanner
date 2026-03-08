from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_security = HTTPBearer(auto_error=False)


def require_verdict_api_key(expected_key: str):
    """Returns a FastAPI dependency that validates VERDICT_API_KEY."""

    async def verify(
        creds: HTTPAuthorizationCredentials | None = Depends(_security),
    ) -> str:
        if creds is None or not hmac.compare_digest(
            creds.credentials, expected_key
        ):
            raise HTTPException(status_code=401)
        return creds.credentials

    return verify
