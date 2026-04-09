"""Async API clients for ZeroMOUSE cloud services."""

import hashlib
import hmac
import logging
import time
from datetime import datetime, timezone
from urllib.parse import quote

import aiohttp

from .const import (
    COGNITO_CLIENT_ID,
    COGNITO_ENDPOINT,
    COGNITO_IDENTITY_ENDPOINT,
    COGNITO_IDENTITY_POOL_ID,
    COGNITO_USER_POOL_ID,
    GRAPHQL_URL,
    S3_BUCKET,
    S3_REGION,
    SHADOW_API_URL,
    TOKEN_REFRESH_MARGIN,
)

_LOGGER = logging.getLogger(__name__)

EVENT_QUERY = """
query listMbrPtfEventDataWithImages(
  $deviceID: String!,
  $sortDirection: ModelSortDirection,
  $filter: ModelMbrPtfEventDataFilterInput,
  $limit: Int
) {
  listEventbyDeviceChrono(
    deviceID: $deviceID,
    sortDirection: $sortDirection,
    filter: $filter,
    limit: $limit
  ) {
    items {
      eventID
      eventTime
      type
      classification_byNet
      catClusterId
      titleImageIndex
      createdAt
      Images {
        items {
          filePath
        }
      }
    }
  }
}
"""


class ZeromouseAuthError(Exception):
    """Raised when authentication fails (bad or expired refresh token)."""


class ZeromouseApiError(Exception):
    """Raised when an API call fails (network, server error, etc.)."""


def _s3_presign_url(
    bucket: str,
    key: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str,
    expires: int = 900,
) -> str:
    """Generate a pre-signed S3 GetObject URL (SigV4 query string auth)."""
    host = f"{bucket}.s3.{region}.amazonaws.com"
    now = datetime.now(timezone.utc)
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    credential_scope = f"{datestamp}/{region}/s3/aws4_request"
    credential = f"{access_key}/{credential_scope}"

    encoded_key = quote(key, safe="/~")

    query_params = (
        f"X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential={quote(credential, safe='')}"
        f"&X-Amz-Date={amz_date}"
        f"&X-Amz-Expires={expires}"
        f"&X-Amz-Security-Token={quote(session_token, safe='')}"
        f"&X-Amz-SignedHeaders=host"
    )

    canonical_request = (
        f"GET\n/{encoded_key}\n{query_params}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
    )

    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        + hashlib.sha256(canonical_request.encode()).hexdigest()
    )

    def _sign(key_bytes: bytes, msg: str) -> bytes:
        return hmac.new(key_bytes, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(
        _sign(
            _sign(
                _sign(f"AWS4{secret_key}".encode(), datestamp),
                region,
            ),
            "s3",
        ),
        "aws4_request",
    )
    signature = hmac.new(
        signing_key, string_to_sign.encode(), hashlib.sha256
    ).hexdigest()

    return f"https://{host}/{encoded_key}?{query_params}&X-Amz-Signature={signature}"


class CognitoAuth:
    """Manages Cognito token lifecycle and AWS credentials."""

    def __init__(self, session: aiohttp.ClientSession, refresh_token: str) -> None:
        self._session = session
        self._refresh_token = refresh_token
        self._id_token: str | None = None
        self._token_expiry: float = 0
        # Cognito Identity credentials (for S3 image access)
        self._identity_id: str | None = None
        self._aws_access_key: str | None = None
        self._aws_secret_key: str | None = None
        self._aws_session_token: str | None = None

    @property
    def id_token(self) -> str | None:
        return self._id_token

    @property
    def identity_id(self) -> str | None:
        return self._identity_id

    async def async_ensure_valid_token(self) -> None:
        """Refresh the token if it's within TOKEN_REFRESH_MARGIN of expiry."""
        if time.time() < self._token_expiry - TOKEN_REFRESH_MARGIN:
            return
        await self._async_refresh()

    def presign_s3_url(self, file_path: str) -> str:
        """Generate a pre-signed S3 URL for an event image."""
        if not self._identity_id or not self._aws_access_key:
            return ""
        key = f"private/{self._identity_id}/{file_path}"
        return _s3_presign_url(
            S3_BUCKET,
            key,
            S3_REGION,
            self._aws_access_key,
            self._aws_secret_key,
            self._aws_session_token,
        )

    async def _async_cognito_identity_post(self, target: str, body: dict) -> dict:
        """POST to the Cognito Identity endpoint."""
        async with self._session.post(
            COGNITO_IDENTITY_ENDPOINT,
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": f"AWSCognitoIdentityService.{target}",
            },
            json=body,
        ) as resp:
            if resp.status != 200:
                body_text = await resp.text()
                raise ZeromouseApiError(
                    f"Cognito Identity {target} failed (HTTP {resp.status}): {body_text[:200]}"
                )
            return await resp.json(content_type=None)

    async def _async_refresh(self) -> None:
        """Exchange refresh token for a new IdToken + AWS credentials."""
        _LOGGER.debug("Refreshing Cognito tokens")
        # Step 1: Get IdToken via refresh token
        try:
            async with self._session.post(
                COGNITO_ENDPOINT,
                headers={
                    "Content-Type": "application/x-amz-json-1.1",
                    "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
                },
                json={
                    "ClientId": COGNITO_CLIENT_ID,
                    "AuthFlow": "REFRESH_TOKEN_AUTH",
                    "AuthParameters": {
                        "REFRESH_TOKEN": self._refresh_token,
                    },
                },
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise ZeromouseAuthError(
                        f"Cognito auth failed (HTTP {resp.status}): {body[:200]}"
                    )
                data = await resp.json(content_type=None)
        except aiohttp.ClientError as err:
            raise ZeromouseApiError(f"Cognito request failed: {err}") from err

        result = data.get("AuthenticationResult")
        if not result or "IdToken" not in result:
            raise ZeromouseAuthError("Cognito response missing AuthenticationResult")

        self._id_token = result["IdToken"]
        self._token_expiry = time.time() + result.get("ExpiresIn", 3600)
        _LOGGER.debug("IdToken refreshed, valid for %ds", result.get("ExpiresIn", 3600))

        # Step 2: Get Cognito Identity ID + temp AWS credentials (for S3)
        login_key = f"cognito-idp.{S3_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        logins = {login_key: self._id_token}

        try:
            id_data = await self._async_cognito_identity_post(
                "GetId",
                {"IdentityPoolId": COGNITO_IDENTITY_POOL_ID, "Logins": logins},
            )
            self._identity_id = id_data["IdentityId"]

            creds_data = await self._async_cognito_identity_post(
                "GetCredentialsForIdentity",
                {"IdentityId": self._identity_id, "Logins": logins},
            )
            creds = creds_data["Credentials"]
            self._aws_access_key = creds["AccessKeyId"]
            self._aws_secret_key = creds["SecretKey"]
            self._aws_session_token = creds["SessionToken"]
            _LOGGER.debug("AWS credentials obtained for identity %s", self._identity_id)
        except (aiohttp.ClientError, KeyError) as err:
            _LOGGER.warning("Could not get AWS credentials for S3 images: %s", err)
            # Non-fatal — sensors still work, just no image URLs


class ShadowClient:
    """Fetches device shadow state via the ZeroMOUSE REST API."""

    def __init__(
        self, auth: CognitoAuth, session: aiohttp.ClientSession, device_id: str
    ) -> None:
        self._auth = auth
        self._session = session
        self._device_id = device_id

    async def async_get_shadow(self) -> dict:
        """Fetch the full device shadow. Returns the shadow dict."""
        await self._auth.async_ensure_valid_token()
        try:
            async with self._session.get(
                SHADOW_API_URL,
                params={"deviceID": self._device_id},
                headers={"auth-token": self._auth.id_token},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 401 or resp.status == 403:
                    raise ZeromouseAuthError("Shadow API auth failed (token expired?)")
                if resp.status != 200:
                    body = await resp.text()
                    raise ZeromouseApiError(
                        f"Shadow API error (HTTP {resp.status}): {body[:200]}"
                    )
                return await resp.json(content_type=None)
        except aiohttp.ClientError as err:
            raise ZeromouseApiError(f"Shadow API request failed: {err}") from err


class EventClient:
    """Fetches detection events via the ZeroMOUSE AppSync GraphQL API."""

    def __init__(
        self, auth: CognitoAuth, session: aiohttp.ClientSession, device_id: str
    ) -> None:
        self._auth = auth
        self._session = session
        self._device_id = device_id

    async def async_get_latest_events(self, limit: int = 5) -> list[dict]:
        """Fetch the latest detection events. Returns a list of event dicts."""
        await self._auth.async_ensure_valid_token()
        try:
            async with self._session.post(
                GRAPHQL_URL,
                headers={
                    "Authorization": self._auth.id_token,
                    "Content-Type": "application/json",
                },
                json={
                    "query": EVENT_QUERY,
                    "variables": {
                        "deviceID": self._device_id,
                        "limit": limit,
                        "sortDirection": "DESC",
                        "filter": {
                            "classification_byNet": {"ne": "free"},
                        },
                    },
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 401 or resp.status == 403:
                    raise ZeromouseAuthError("GraphQL auth failed (token expired?)")
                if resp.status != 200:
                    body = await resp.text()
                    raise ZeromouseApiError(
                        f"GraphQL error (HTTP {resp.status}): {body[:200]}"
                    )
                data = await resp.json(content_type=None)
        except aiohttp.ClientError as err:
            raise ZeromouseApiError(f"GraphQL request failed: {err}") from err

        return (
            data.get("data", {})
            .get("listEventbyDeviceChrono", {})
            .get("items", [])
        )

    def get_image_url(self, file_path: str) -> str:
        """Generate a pre-signed S3 URL for an event image."""
        return self._auth.presign_s3_url(file_path)


async def async_validate_credentials(
    session: aiohttp.ClientSession,
    device_id: str,
    refresh_token: str,
) -> dict:
    """Validate credentials by refreshing the token and fetching the shadow.

    Returns the shadow dict on success.
    Raises ZeromouseAuthError or ZeromouseApiError on failure.
    """
    auth = CognitoAuth(session, refresh_token)
    await auth.async_ensure_valid_token()
    client = ShadowClient(auth, session, device_id)
    return await client.async_get_shadow()
