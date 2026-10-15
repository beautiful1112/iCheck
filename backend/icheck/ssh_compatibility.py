"""Per-connection SSH policies for the native Netmiko runtime.

No monkey patches or dependency downgrades. The legacy adapter reuses Paramiko
5's DH and RSA implementations, with isolated algorithm maps and hash selection.
Keep the pinned dependency and wire-level tests in sync when upgrading Paramiko.
"""
from functools import lru_cache
from hashlib import sha1
from importlib.metadata import version

MODERN = "modern"
LEGACY = "legacy_cisco_v1"
PROFILES = (MODERN, LEGACY)
CONFIG_KEY = "studio_ssh_compatibility"
TARGET_FIELDS = ("device_id", "connection_id", "host", "port", "identity_revision")


def validate_profile(profile):
    if profile not in PROFILES:
        raise ValueError("Unknown SSH compatibility profile")
    return profile


def connection_profile(configuration, target):
    record = configuration.get(CONFIG_KEY)
    if record is None:
        return MODERN, True
    if not isinstance(record, dict):
        raise ValueError("Invalid SSH compatibility configuration")
    profile = validate_profile(record.get("profile"))
    current = profile == MODERN or all(record.get(field) == target[field] for field in TARGET_FIELDS)
    return profile, current


@lru_cache(maxsize=1)
def _legacy_transport_class():
    import paramiko
    from cryptography.hazmat.primitives import hashes
    from paramiko.kex_group14 import KexGroup14SHA256

    # Only select different algorithms; retain the library's packet, DH range,
    # signature verification, strict-KEX and channel implementations.
    class Group14SHA1(KexGroup14SHA256):
        name = "diffie-hellman-group14-sha1"
        hash_algo = sha1

    class LegacyRSAKey(paramiko.RSAKey):
        HASHES = {**paramiko.RSAKey.HASHES, "ssh-rsa": hashes.SHA1}

    class LegacyTransport(paramiko.Transport):
        _kex_info = {**paramiko.Transport._kex_info, Group14SHA1.name: Group14SHA1}
        _key_info = {**paramiko.Transport._key_info, "ssh-rsa": LegacyRSAKey}
        _preferred_kex = (*paramiko.Transport._preferred_kex, Group14SHA1.name)
        _preferred_keys = (*paramiko.Transport._preferred_keys, "ssh-rsa")

    return LegacyTransport


def transport_factory(profile=MODERN):
    """Construct a transport for this connection only; never retry/downgrade."""
    validate_profile(profile)
    import paramiko
    if version("paramiko") != "5.0.0":
        raise ValueError("The reviewed SSH runtime requires Paramiko 5.0.0")
    cls = _legacy_transport_class() if profile == LEGACY else paramiko.Transport

    def create(sock, **kwargs):
        transport = cls(sock, **kwargs)
        options = transport.get_security_options()
        # Legacy CBC cannot pair with ETM MACs on pre-strict-KEX devices.
        options.ciphers = ("aes128-ctr", "aes192-ctr", "aes256-ctr",
            "aes128-gcm@openssh.com", "aes256-gcm@openssh.com") + (
            ("aes128-cbc", "aes192-cbc", "aes256-cbc") if profile == LEGACY else ())
        options.digests = (("hmac-sha2-256", "hmac-sha2-512", "hmac-sha1") if profile == LEGACY else
            ("hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"))
        return transport
    return create


def netmiko_connection(profile=MODERN, **kwargs):
    """Inject a transport through a connection-local Netmiko client hook."""
    import paramiko
    from netmiko.ssh_dispatcher import ssh_dispatcher
    factory = transport_factory(profile)

    class ProfileClient(paramiko.SSHClient):
        def connect(self, *args, **options):
            return super().connect(*args, **options, transport_factory=factory)

    driver = ssh_dispatcher(kwargs["device_type"])

    class ProfileConnection(driver):
        def _get_ssh_client_instance(self):
            return ProfileClient()

    return ProfileConnection(**kwargs)
