"""Minimal AWS Cognito SRP authentication (no boto3 dependency).

Implements USER_SRP_AUTH flow using only stdlib + aiohttp.
Based on https://github.com/aws/amazon-cognito-identity-js
"""

import base64
import binascii
import hashlib
import hmac
import os
import re

import aiohttp

# RFC 5054 3072-bit prime
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
G_HEX = "2"
INFO_BITS = bytearray("Caldera Derived Key", "utf-8")

N = int(N_HEX, 16)
G = int(G_HEX, 16)


def _pad_hex(value: int | str) -> str:
    h = f"{value:x}" if isinstance(value, int) else value
    if len(h) % 2 == 1:
        h = "0" + h
    elif h[0] in "89ABCDEFabcdef":
        h = "00" + h
    return h


K = int(
    hashlib.sha256(bytes.fromhex(_pad_hex(N) + _pad_hex(G))).hexdigest(),
    16,
)

WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _hex_hash(hex_str: str) -> str:
    v = hashlib.sha256(bytes.fromhex(hex_str)).hexdigest()
    return v.zfill(64)


def _compute_hkdf(ikm: bytes, salt: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, INFO_BITS + b"\x01", hashlib.sha256).digest()[:16]


def _cognito_timestamp() -> str:
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        f"{WEEKDAYS[now.weekday()]} {MONTHS[now.month - 1]} "
        f"{now.day} {now.hour:02d}:{now.minute:02d}:{now.second:02d} UTC {now.year}"
    )


class SRPAuth:
    """Performs Cognito USER_SRP_AUTH flow using aiohttp."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        pool_id: str,
        client_id: str,
        region: str,
    ):
        self._session = session
        self._username = username
        self._password = password
        self._pool_id = pool_id
        self._pool_id_short = pool_id.split("_")[1]
        self._client_id = client_id
        self._endpoint = f"https://cognito-idp.{region}.amazonaws.com/"
        # Generate ephemeral keys
        self._small_a = int.from_bytes(os.urandom(128), "big")
        self._large_a = pow(G, self._small_a, N)

    async def authenticate(self) -> dict:
        """Run the full SRP flow. Returns AuthenticationResult with tokens."""
        # Step 1: InitiateAuth
        init_resp = await self._post(
            "AWSCognitoIdentityProviderService.InitiateAuth",
            {
                "ClientId": self._client_id,
                "AuthFlow": "USER_SRP_AUTH",
                "AuthParameters": {
                    "USERNAME": self._username,
                    "SRP_A": format(self._large_a, "x"),
                },
            },
        )

        if init_resp.get("ChallengeName") != "PASSWORD_VERIFIER":
            raise Exception(
                f"Unexpected challenge: {init_resp.get('ChallengeName')}"
            )

        # Step 2: Compute challenge response
        params = init_resp["ChallengeParameters"]
        response = self._process_challenge(params)

        # Step 3: RespondToAuthChallenge
        auth_resp = await self._post(
            "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
            {
                "ClientId": self._client_id,
                "ChallengeName": "PASSWORD_VERIFIER",
                "ChallengeResponses": response,
            },
        )

        if "AuthenticationResult" not in auth_resp:
            raise Exception(
                f"Auth failed: {auth_resp.get('ChallengeName', auth_resp)}"
            )

        return auth_resp["AuthenticationResult"]

    def _process_challenge(self, params: dict) -> dict:
        user_id = params["USER_ID_FOR_SRP"]
        salt_hex = params["SALT"]
        srp_b_hex = params["SRP_B"]
        secret_block = params["SECRET_BLOCK"]
        timestamp = _cognito_timestamp()

        big_b = int(srp_b_hex, 16)
        if big_b % N == 0:
            raise ValueError("SRP B cannot be zero")

        # u = H(A|B)
        u = int(
            _hex_hash(_pad_hex(self._large_a) + _pad_hex(big_b)),
            16,
        )
        if u == 0:
            raise ValueError("SRP u cannot be zero")

        # x = H(salt | H(poolId | userId | ":" | password))
        user_pass_hash = hashlib.sha256(
            f"{self._pool_id_short}{user_id}:{self._password}".encode()
        ).hexdigest()
        x = int(_hex_hash(_pad_hex(salt_hex) + user_pass_hash), 16)

        # S = (B - k * g^x) ^ (a + u * x) mod N
        s = pow(big_b - K * pow(G, x, N), self._small_a + u * x, N)

        # Derive key
        hkdf = _compute_hkdf(
            bytes.fromhex(_pad_hex(s)),
            bytes.fromhex(_pad_hex(u)),
        )

        # Compute signature
        msg = (
            self._pool_id_short.encode()
            + user_id.encode()
            + base64.b64decode(secret_block)
            + timestamp.encode()
        )
        sig = base64.b64encode(
            hmac.new(hkdf, msg, hashlib.sha256).digest()
        ).decode()

        return {
            "TIMESTAMP": timestamp,
            "USERNAME": user_id,
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block,
            "PASSWORD_CLAIM_SIGNATURE": sig,
        }

    async def _post(self, target: str, body: dict) -> dict:
        async with self._session.post(
            self._endpoint,
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": target,
            },
            json=body,
        ) as resp:
            data = await resp.json(content_type=None)
            if resp.status != 200:
                error = data.get("message", data.get("__type", "Unknown error"))
                raise Exception(f"Cognito error: {error}")
            return data
