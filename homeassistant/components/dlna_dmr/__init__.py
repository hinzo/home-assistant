"""The dlna_dmr component."""
from __future__ import annotations

from homeassistant import config_entries
from homeassistant.components.media_player.const import DOMAIN as MEDIA_PLAYER_DOMAIN
from homeassistant.core import HomeAssistant

from .const import LOGGER

PLATFORMS = [MEDIA_PLAYER_DOMAIN]


async def async_setup_entry(
    hass: HomeAssistant, entry: config_entries.ConfigEntry
) -> bool:
    """Set up a DLNA DMR device from a config entry."""
    LOGGER.debug("Setting up config entry: %s", entry.unique_id)

    # Forward setup to the appropriate platform
    hass.config_entries.async_setup_platforms(entry, PLATFORMS)

    return True


async def async_unload_entry(
    hass: HomeAssistant, config_entry: config_entries.ConfigEntry
) -> bool:
    """Unload a config entry."""
    # Forward to the same platform as async_setup_entry did
    return await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)
