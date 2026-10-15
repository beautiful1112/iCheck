from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class SSHCommandProfile:
    key: str
    command: str
    description: str
    platform: str


_PROFILES = {
    "linux.ip_address_json": SSHCommandProfile(
        key="linux.ip_address_json",
        command="ip -json address show",
        description="Linux interface, IP address, and link inventory",
        platform="linux",
    ),
    "linux.route_json": SSHCommandProfile(
        key="linux.route_json",
        command="ip -json route show",
        description="Linux routing table inventory",
        platform="linux",
    ),
    "cisco_nxos.show_version_json": SSHCommandProfile(
        key="cisco_nxos.show_version_json",
        command="show version | json",
        description="Cisco NX-OS software and chassis inventory",
        platform="cisco_nxos",
    ),
    "cisco_nxos.show_interface_status_json": SSHCommandProfile(
        key="cisco_nxos.show_interface_status_json",
        command="show interface status | json",
        description="Cisco NX-OS interface status inventory",
        platform="cisco_nxos",
    ),
}


SSH_COMMAND_PROFILES = MappingProxyType(_PROFILES)


def get_ssh_command_profile(value: object) -> SSHCommandProfile:
    if not isinstance(value, str) or value not in SSH_COMMAND_PROFILES:
        raise ValueError(f"Unsupported fixed SSH command profile: {value!r}")
    return SSH_COMMAND_PROFILES[value]
