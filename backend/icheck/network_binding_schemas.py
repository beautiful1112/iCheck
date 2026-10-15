"""Explicit, bounded port/VLAN and address/VLAN sets; never physical proof."""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from .models import ObservationSource
from .schemas import APIModel, normalize_ip, normalize_mac

NETWORK_OBSERVATION_V2 = "icheck.inventory.network-observation/v2"


class NetworkBindingModel(APIModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class NetworkAddressBinding(NetworkBindingModel):
    ip_address: str
    vlan_id: int | None = Field(default=None, strict=True, ge=1, le=4094)

    @field_validator("ip_address")
    @classmethod
    def address(cls, value: str) -> str:
        return normalize_ip(value)


class NetworkAttachmentBinding(NetworkBindingModel):
    interface_name: str = Field(min_length=1, max_length=255)
    vlan_id: int | None = Field(default=None, strict=True, ge=1, le=4094)

    @field_validator("interface_name")
    @classmethod
    def interface(cls, value: str) -> str:
        if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Interface names cannot have surrounding whitespace or control characters")
        return value


def address_binding_key(item: NetworkAddressBinding) -> tuple:
    address = ipaddress.ip_address(item.ip_address)
    return (address.version, int(address), item.ip_address, item.vlan_id or 0)


class NetworkObservationFieldsV2(NetworkBindingModel):
    mac_address: str
    source: Literal[ObservationSource.ARP, ObservationSource.MAC_TABLE, ObservationSource.DHCP, ObservationSource.MANUAL]
    collector_device_id: str | None = Field(default=None, min_length=1, max_length=36)
    ip_bindings: list[NetworkAddressBinding] | None = Field(default=None, max_length=256)
    ip_family_scope: Literal["ipv4", "ipv6", "dual_stack"] | None = None
    attachments: list[NetworkAttachmentBinding] | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=128)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac_address")
    @classmethod
    def mac(cls, value: str) -> str:
        return normalize_mac(value)

    @model_validator(mode="after")
    def coherent_sets(self):
        if (self.ip_bindings is None) != (self.ip_family_scope is None):
            raise ValueError("Observed IP binding sets require an explicit ip_family_scope; omitted sets cannot declare one")
        if self.ip_bindings is not None:
            allowed = {"ipv4": {4}, "ipv6": {6}, "dual_stack": {4, 6}}[self.ip_family_scope]
            if any(ipaddress.ip_address(item.ip_address).version not in allowed for item in self.ip_bindings):
                raise ValueError("Every IP binding must belong to its declared family scope")
            keys = [(item.ip_address, item.vlan_id) for item in self.ip_bindings]
            if len(keys) != len(set(keys)):
                raise ValueError("IP binding sets cannot repeat a normalized address/VLAN pair")
            self.ip_bindings = sorted(self.ip_bindings, key=address_binding_key)
        if self.attachments is not None:
            keys = [(item.interface_name, item.vlan_id) for item in self.attachments]
            if len(keys) != len(set(keys)):
                raise ValueError("Attachment sets cannot repeat an interface/VLAN pair")
            self.attachments = sorted(self.attachments, key=lambda item: (item.interface_name, item.vlan_id or 0))
        return self


class NetworkObservationV2(NetworkObservationFieldsV2):
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def utc_clock(self):
        stamp = self.observed_at
        self.observed_at = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
        return self


class NetworkObservationBatchV2(NetworkBindingModel):
    observations: list[NetworkObservationV2] = Field(min_length=1, max_length=2000)
