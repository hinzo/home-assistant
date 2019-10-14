"""Helper functions for Philips Hue."""
from homeassistant.helpers.entity_registry import async_get_registry as get_ent_reg
from homeassistant.helpers.device_registry import async_get_registry as get_dev_reg

from .const import DOMAIN


async def get_removed_devices(hass, config_entry, api_ids, current):
    """Get items that are removed from api."""
    removed_items = []

    for item_id in current:
        if item_id in api_ids:
            continue

        # Device is removed from Hue, so we remove it from Home Assistant
        entity = current[item_id]
        removed_items.append(item_id)
        await entity.async_remove()
        ent_registry = await get_ent_reg(hass)
        if entity.entity_id in ent_registry.entities:
            ent_registry.async_remove(entity.entity_id)
        dev_registry = await get_dev_reg(hass)
        device = dev_registry.async_get_device(
            identifiers={(DOMAIN, entity.unique_id)}, connections=set()
        )
        dev_registry.async_update_device(
            device.id, remove_config_entry_id=config_entry.entry_id
        )

    return removed_items
