from typing import Literal
from pydantic import ConfigDict, Field, SecretStr, model_validator
from .schemas import APIModel

CredentialKind = Literal["snmp_v2c", "windows_password", "https_token", "http_basic", "ssh_password", "ssh_key"]


class DeviceCredentialCreate(APIModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    site: str = Field(min_length=1, max_length=128)
    kind: CredentialKind
    username: str | None = Field(default=None, min_length=1, max_length=255)
    community: SecretStr | None = Field(default=None, min_length=1, max_length=255)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=4096)
    token: SecretStr | None = Field(default=None, min_length=1, max_length=4096)
    private_key: SecretStr | None = Field(default=None, min_length=32, max_length=32000)
    private_key_passphrase: SecretStr | None = Field(default=None, min_length=1, max_length=4096)

    @model_validator(mode="after")
    def exact_fields(self):
        allowed = {"snmp_v2c": {"community"}, "https_token": {"token"},
                   "windows_password": {"username", "password"}, "http_basic": {"username", "password"}, "ssh_password": {"username", "password"},
                   "ssh_key": {"username", "private_key", "private_key_passphrase"}}[self.kind]
        supplied = {k for k in ("username", "community", "password", "token", "private_key", "private_key_passphrase")
                    if getattr(self, k) is not None}
        if supplied - allowed or (allowed - {"private_key_passphrase"}) - supplied:
            raise ValueError("Provide exactly the credential fields required for the selected type")
        for key in supplied - {"private_key"}:
            item = getattr(self, key)
            value = item.get_secret_value() if isinstance(item, SecretStr) else item
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError("Credential fields must not contain control characters")
        if self.private_key is not None:
            import asyncssh
            try:
                asyncssh.import_private_key(self.private_key.get_secret_value(),
                    passphrase=self.private_key_passphrase.get_secret_value() if self.private_key_passphrase else None)
            except (ValueError, asyncssh.KeyImportError):
                raise ValueError("SSH private key or passphrase is invalid") from None
        if not self.site.strip() or self.site != self.site.strip():
            raise ValueError("Site must be nonempty without surrounding whitespace")
        return self


class DeviceCredentialUpdate(DeviceCredentialCreate):
    expected_revision: int = Field(ge=1)
    enabled: bool = True
    reason: str = Field(min_length=1, max_length=1000)


class DeviceCredentialRevoke(APIModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1000)
