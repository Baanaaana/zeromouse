"""Config flow for ZeroMOUSE integration."""

import base64
import json
import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    ZeromouseApiError,
    ZeromouseAuthError,
    async_list_devices,
    async_login,
    async_validate_credentials,
)
from .const import CONF_DEVICE_ID, CONF_DEVICE_NAME, CONF_REFRESH_TOKEN, DOMAIN

_LOGGER = logging.getLogger(__name__)


class ZeromouseConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ZeroMOUSE."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._refresh_token: str | None = None
        self._access_token: str | None = None
        self._owner_id: str | None = None
        self._devices: list[dict] = []

    async def async_step_user(self, user_input=None):
        """Step 1: Email + password login."""
        errors = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            try:
                result = await async_login(
                    session,
                    user_input["email"],
                    user_input["password"],
                )
            except ZeromouseAuthError as err:
                _LOGGER.error("ZeroMOUSE login failed: %s", err)
                errors["base"] = "invalid_auth"
            except ZeromouseApiError as err:
                _LOGGER.error("ZeroMOUSE API error: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during login")
                errors["base"] = "unknown"
            else:
                # Store tokens for next step
                self._refresh_token = result["RefreshToken"]
                self._access_token = result["AccessToken"]

                # Extract owner ID from IdToken
                payload = result["IdToken"].split(".")[1]
                payload += "=" * (4 - len(payload) % 4)
                claims = json.loads(base64.b64decode(payload))
                self._owner_id = claims["sub"]

                # Discover devices
                try:
                    self._devices = await async_list_devices(
                        session, self._access_token, self._owner_id
                    )
                except Exception:
                    _LOGGER.exception("Device discovery failed")
                    self._devices = []

                if not self._devices:
                    errors["base"] = "no_devices"
                else:
                    return await self.async_step_select_device()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("email"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
        )

    async def async_step_select_device(self, user_input=None):
        """Step 2: Select device from discovered list."""
        errors = {}

        if user_input is not None:
            device_id = user_input[CONF_DEVICE_ID]

            # Find device name
            device_name = "ZeroMOUSE"
            for d in self._devices:
                if d["device_id"] == device_id:
                    device_name = d["name"]
                    break

            # Verify the device is accessible
            session = async_get_clientsession(self.hass)
            try:
                await async_validate_credentials(
                    session, device_id, self._refresh_token
                )
            except (ZeromouseAuthError, ZeromouseApiError) as err:
                _LOGGER.error("Device validation failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during device validation")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(device_id)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=device_name,
                    data={
                        CONF_DEVICE_ID: device_id,
                        CONF_DEVICE_NAME: device_name,
                        CONF_REFRESH_TOKEN: self._refresh_token,
                    },
                )

        # Build device dropdown
        device_options = {
            d["device_id"]: f"{d['name']} ({d['device_id'][:8]}...)"
            for d in self._devices
        }

        # Auto-select if only one device
        if len(self._devices) == 1 and user_input is None:
            return await self.async_step_select_device(
                {CONF_DEVICE_ID: self._devices[0]["device_id"]}
            )

        return self.async_show_form(
            step_id="select_device",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DEVICE_ID): vol.In(device_options),
                }
            ),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data):
        """Handle re-authentication when the refresh token expires."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Re-auth with email + password."""
        errors = {}
        reauth_entry = self._get_reauth_entry()

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            try:
                result = await async_login(
                    session,
                    user_input["email"],
                    user_input["password"],
                )
            except ZeromouseAuthError as err:
                _LOGGER.error("ZeroMOUSE reauth failed: %s", err)
                errors["base"] = "invalid_auth"
            except ZeromouseApiError as err:
                _LOGGER.error("ZeroMOUSE API error: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during reauth")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data={
                        **reauth_entry.data,
                        CONF_REFRESH_TOKEN: result["RefreshToken"],
                    },
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required("email"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
        )
