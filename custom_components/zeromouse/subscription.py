"""AppSync WebSocket subscription manager for real-time event updates."""

import asyncio
import base64
import json
import logging
import uuid

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import CognitoAuth
from .const import APPSYNC_HOST, APPSYNC_REALTIME_URL

_LOGGER = logging.getLogger(__name__)

# Subscription queries
EVENT_SUBSCRIPTION = """
subscription onCreateMbrPtfEventData {
  onCreateMbrPtfEventData {
    eventID
    eventTime
    type
    classification_byNet
    deviceID
  }
}
"""

RECONNECT_DELAYS = [1, 2, 5, 10, 30, 60]  # exponential backoff seconds
KEEPALIVE_TIMEOUT = 300  # seconds — disconnect if no ka received


class AppSyncSubscriptionManager:
    """Manages AppSync WebSocket subscriptions for instant event updates."""

    def __init__(
        self,
        hass: HomeAssistant,
        session: aiohttp.ClientSession,
        auth: CognitoAuth,
        event_coordinator: DataUpdateCoordinator,
        shadow_coordinator: DataUpdateCoordinator,
        device_id: str,
    ) -> None:
        self._hass = hass
        self._session = session
        self._auth = auth
        self._event_coordinator = event_coordinator
        self._shadow_coordinator = shadow_coordinator
        self._device_id = device_id
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._listen_task: asyncio.Task | None = None
        self._stopping = False
        self._reconnect_count = 0

    async def async_start(self) -> None:
        """Start the WebSocket connection and listener."""
        self._stopping = False
        self._listen_task = self._hass.async_create_background_task(
            self._async_run(), "zeromouse_subscription"
        )
        _LOGGER.info("AppSync subscription manager started")

    async def async_stop(self) -> None:
        """Stop the WebSocket connection."""
        self._stopping = True
        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        _LOGGER.info("AppSync subscription manager stopped")

    async def _async_run(self) -> None:
        """Main loop: connect, listen, reconnect on failure."""
        while not self._stopping:
            try:
                await self._async_connect_and_listen()
            except asyncio.CancelledError:
                break
            except Exception:
                _LOGGER.exception("AppSync WebSocket error")

            if self._stopping:
                break

            # Reconnect with backoff
            delay = RECONNECT_DELAYS[
                min(self._reconnect_count, len(RECONNECT_DELAYS) - 1)
            ]
            self._reconnect_count += 1
            _LOGGER.info("AppSync reconnecting in %ds (attempt %d)", delay, self._reconnect_count)
            await asyncio.sleep(delay)

    async def _async_connect_and_listen(self) -> None:
        """Connect to AppSync WebSocket, register subscriptions, and listen."""
        await self._auth.async_ensure_valid_token()

        # Build connection URL with auth header encoded in query params
        header_payload = json.dumps({
            "host": APPSYNC_HOST,
            "Authorization": self._auth.id_token,
        })
        header_b64 = base64.b64encode(header_payload.encode()).decode()
        payload_b64 = base64.b64encode(b"{}").decode()
        url = f"{APPSYNC_REALTIME_URL}?header={header_b64}&payload={payload_b64}"

        _LOGGER.debug("Connecting to AppSync WebSocket")
        self._ws = await self._session.ws_connect(
            url,
            protocols=["graphql-ws"],
            heartbeat=30,
        )

        # Connection init
        await self._ws.send_json({"type": "connection_init"})

        # Wait for connection_ack
        async for msg in self._ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get("type") == "connection_ack":
                    _LOGGER.info("AppSync WebSocket connected")
                    self._reconnect_count = 0
                    break
                if data.get("type") == "connection_error":
                    _LOGGER.error("AppSync connection error: %s", data.get("payload"))
                    return
            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                _LOGGER.error("AppSync WebSocket closed during handshake")
                return

        # Register event subscription
        sub_id = str(uuid.uuid4())
        await self._ws.send_json({
            "id": sub_id,
            "type": "start",
            "payload": {
                "data": json.dumps({
                    "query": EVENT_SUBSCRIPTION,
                    "variables": {},
                }),
                "extensions": {
                    "authorization": {
                        "Authorization": self._auth.id_token,
                        "host": APPSYNC_HOST,
                    }
                },
            },
        })
        _LOGGER.debug("Registered event subscription: %s", sub_id)

        # Listen for messages
        last_ka = asyncio.get_event_loop().time()

        async for msg in self._ws:
            if self._stopping:
                break

            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)
                msg_type = data.get("type")

                if msg_type == "ka":
                    last_ka = asyncio.get_event_loop().time()

                elif msg_type == "start_ack":
                    _LOGGER.info("AppSync subscription active: %s", data.get("id"))

                elif msg_type == "data":
                    await self._async_handle_data(data)

                elif msg_type == "error":
                    _LOGGER.error("AppSync subscription error: %s", data.get("payload"))

            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                _LOGGER.warning("AppSync WebSocket closed")
                break

            # Check keepalive timeout
            if asyncio.get_event_loop().time() - last_ka > KEEPALIVE_TIMEOUT:
                _LOGGER.warning("AppSync keepalive timeout, reconnecting")
                break

    async def _async_handle_data(self, data: dict) -> None:
        """Handle incoming subscription data."""
        payload = data.get("payload", {}).get("data", {})

        if "onCreateMbrPtfEventData" in payload:
            event = payload["onCreateMbrPtfEventData"]
            # Only refresh if this event is for our device
            if event.get("deviceID") == self._device_id:
                _LOGGER.info(
                    "AppSync: new event %s (%s) for device %s",
                    event.get("type"),
                    event.get("classification_byNet"),
                    event.get("deviceID"),
                )
                # Trigger immediate refresh of both coordinators
                await self._event_coordinator.async_request_refresh()
                await self._shadow_coordinator.async_request_refresh()
