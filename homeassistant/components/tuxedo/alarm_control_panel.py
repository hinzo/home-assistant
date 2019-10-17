"""Interfaces with Tuxedo control panel."""
import logging
import random

import base64
import hmac
import requests
import voluptuous as vol
import urllib
import json
import re
import asyncio

from datetime import timedelta
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from aiohttp.hdrs import CACHE_CONTROL, PRAGMA

from homeassistant.core import callback
import homeassistant.components.alarm_control_panel as alarm
from homeassistant.components.alarm_control_panel import PLATFORM_SCHEMA
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.const import (
    CONF_CODE,
    CONF_URL,
    CONF_NAME,
    CONF_MAC,
    STATE_ALARM_PENDING,
    STATE_ALARM_ARMING,
    STATE_ALARM_ARMED_AWAY,
    STATE_ALARM_ARMED_HOME,
    STATE_ALARM_ARMED_NIGHT,
    STATE_ALARM_DISARMED,
    STATE_UNAVAILABLE,
)
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

DEFAULT_NAME = "Tuxedo"

REGISTER_INTERVAL = timedelta(minutes=30)

CONF_PRIVATE_KEY = "private_key"

API_REV = "API_REV01"
API_BASE_PATH = "/system_http_api/" + API_REV

STATUS_MSG_ARMED_STAY = r"Armed Stay"
STATUS_MSG_ARMED_AWAY = r"Armed Away"
STATUS_MSG_ARMED_INSTANT = r"Armed Instant"
STATUS_MSG_DISARMED = r"Ready To Arm"
STATUS_MSG_TIMER = r"\d\s? Secs Remaining"
STATUS_MSG_NOT_AVAILABLE = r"Not available"
STATUS_MSG_NOT_READY = r"Not Ready Fault"

ARMING_NAME_STAY = "STAY"
ARMING_NAME_AWAY = "STAY"
ARMING_NAME_NIGHT = "NIGHT"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_URL): cv.string,
        vol.Required(CONF_MAC): cv.string,
        vol.Required(CONF_PRIVATE_KEY): cv.string,
        vol.Optional(CONF_CODE): cv.positive_int,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    }
)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up Tuxedo control panel."""
    name = config.get(CONF_NAME)
    code = config.get(CONF_CODE)
    mac = config.get(CONF_MAC).replace(":", "-")
    private_key = config.get(CONF_PRIVATE_KEY)
    url = config.get(CONF_URL)

    tuxedo = TuxedoPanel(name, code, mac, private_key, url)
    add_entities([tuxedo], True)


def _sign_string(value, secret_key):
    return hmac.new(bytes(secret_key, "utf-8"), bytes(value, "utf-8"), sha1).hexdigest()


def _encrypt_data(data, key_string, iv_string):
    key = bytes.fromhex(key_string)
    iv = bytes.fromhex(iv_string)
    encryptor = AES.new(key, AES.MODE_CBC, IV=iv)
    cipher = encryptor.encrypt(pad(data, 16))
    return str(base64.b64encode(cipher), "utf-8")


def _decrypt_data(data, key_string, iv_string):
    raw = base64.b64decode(data)
    key = bytes.fromhex(key_string)
    iv = bytes.fromhex(iv_string)
    encryptor = AES.new(key, AES.MODE_CBC, IV=iv)
    decrypted = unpad(encryptor.decrypt(raw), AES.block_size)
    return str(decrypted, "utf-8")


class TuxedoPanel(alarm.AlarmControlPanel):
    """The Tuxedo panel definition."""

    def __init__(self, name, code, mac, private_key, url):
        """Initialize the Tuxedo status."""

        self._name = name
        self._code = str(code) if code else None
        self._mac = mac
        self._api_key_enc = private_key[0:64]
        self._api_iv_enc = private_key[64:]
        self._url = url
        self._state = STATE_ALARM_PENDING

    async def async_added_to_hass(self):
        """Hookup registration callback."""

        @callback
        def async_register(event_time=None):
            result = self._api_request(
                "/Registration/Register", {"mac": self._mac, "operation": "set"}
            )
            _LOGGER.info("register result: %s", result)

        async_register()
        async_track_time_interval(self.hass, async_register, REGISTER_INTERVAL)

    @property
    def name(self):
        """Return the name of the device."""
        return self._name

    @property
    def code_format(self):
        """Regex for code format or None if no code is required."""
        if self._code is None:
            return alarm.FORMAT_NUMBER
        return None

    @property
    def should_poll(self):
        """We only support polling."""
        return True

    @property
    def state(self):
        """Return the state of the device."""
        return self._state

    def update(self):
        """Return the state of the device."""
        state = None
        result = self._api_request("/GetSecurityStatus", {"operation": "get"})
        if result:
            _LOGGER.info("update result: %s", result)
            status_msg = result["Status"]
            if re.search(STATUS_MSG_DISARMED, status_msg):
                state = STATE_ALARM_DISARMED
            elif re.search(STATUS_MSG_ARMED_STAY, status_msg):
                state = STATE_ALARM_ARMED_HOME
            elif re.search(STATUS_MSG_ARMED_AWAY, status_msg):
                state = STATE_ALARM_ARMED_AWAY
            elif re.search(STATUS_MSG_ARMED_INSTANT, status_msg):
                state = STATE_ALARM_ARMED_NIGHT
            elif re.search(STATUS_MSG_TIMER, status_msg):
                state = STATE_ALARM_ARMING
            elif re.search(STATUS_MSG_NOT_AVAILABLE, status_msg) or re.search(
                STATUS_MSG_NOT_READY, status_msg
            ):
                state = STATE_UNAVAILABLE
        else:
            _LOGGER.error("couldn't fetch status")
        self._state = state

    async def async_alarm_disarm(self, code=None):
        """Send disarm command."""
        await self._api_disarm_request(code)

    async def async_alarm_arm_away(self, code=None):
        """Send arm away command."""
        await self._api_arm_request(ARMING_NAME_AWAY, code)

    async def async_alarm_arm_home(self, code=None):
        """Send arm home command."""
        await self._api_arm_request(ARMING_NAME_STAY, code)

    async def async_alarm_arm_night(self, code=None):
        """Send arm night command."""
        await self._api_arm_request(ARMING_NAME_NIGHT, code)

    async def _api_disarm_request(self, code=None):
        result = self._api_request(
            "/AdvancedSecurity/DisarmWithCode",
            {"pID": "1", "ucode": code or self._code, "operation": "set"},
        )
        _LOGGER.info("api_disarm_request result: %s", result)
        if result:
            await asyncio.sleep(2)
            self.async_schedule_update_ha_state()

    async def _api_arm_request(self, arm_name, code=None):
        result = self._api_request(
            "/AdvancedSecurity/ArmWithCode",
            {
                "arming": arm_name,
                "pID": "1",
                "ucode": code or self._code,
                "operation": "set",
            },
        )
        _LOGGER.info("api_arm_request %s result: %s", arm_name, result)
        if result:
            await asyncio.sleep(2)
            self.async_schedule_update_ha_state()

    def _api_request(self, api_name, params):
        uri_params = urllib.parse.urlencode(params)
        _LOGGER.info("api_name: %s, uri_params: %s", api_name, uri_params)
        uri_params_encrypted = _encrypt_data(
            bytes(uri_params, "utf-8"), self._api_key_enc, self._api_iv_enc
        )

        full_url = self._url + API_BASE_PATH + api_name
        header = "MACID:" + self._mac + ",Path:" + API_REV + api_name
        authtoken = _sign_string(header, self._api_key_enc)

        response = requests.post(
            full_url,
            data={
                "param": uri_params_encrypted,
                "len": len(urllib.parse.quote_plus(uri_params_encrypted)),
                "tstamp": random.random(),
            },
            headers={
                "authtoken": authtoken,
                "identity": self._api_iv_enc,
                PRAGMA: "no-cache",
                CACHE_CONTROL: "no-cache",
            },
            verify=False,
        )

        result = None
        if response.status_code == 200:
            content = json.loads(response.content)
            result = _decrypt_data(
                content["Result"], self._api_key_enc, self._api_iv_enc
            )
            result = json.loads(result)
        elif response.status_code == 401:
            # Unauthorized
            _LOGGER.error("Unauthorized, API: %s", api_name)
        elif response.status_code == 405:
            # Method Not Allowed
            _LOGGER.error("Method Not Allowed, API: %s", api_name)
        else:
            # Unknown
            _LOGGER.error(
                "Unknown error, status_code: %s, API: %s",
                response.status_code,
                api_name,
            )
        return result
