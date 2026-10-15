from __future__ import annotations

import asyncio
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AsyncSSHCommandExecutor:
    """Run a fixed command with explicit credentials and host-key checking."""

    known_hosts_file: str

    def __post_init__(self) -> None:
        path = Path(self.known_hosts_file)
        if not path.is_absolute():
            raise ValueError("SSH known_hosts file must be an absolute path")
        if not path.is_file():
            raise ValueError("SSH known_hosts file does not exist")

    def __call__(
        self,
        *,
        host: str,
        port: int,
        credential_profile_ref: str,
        credential: dict[str, str],
        command_profile: str,
        command: str,
        timeout_seconds: int,
    ) -> str:
        del credential_profile_ref, command_profile
        return asyncio.run(
            self._execute(
                host=host,
                port=port,
                credential=credential,
                command=command,
                timeout_seconds=timeout_seconds,
            )
        )

    async def _execute(
        self,
        *,
        host: str,
        port: int,
        credential: dict[str, str],
        command: str,
        timeout_seconds: int,
    ) -> str:
        try:
            asyncssh = importlib.import_module("asyncssh")
        except ImportError as exc:
            raise RuntimeError(
                "SSH command execution requires the asyncssh package"
            ) from exc

        username = credential.get("username")
        if not isinstance(username, str) or not username:
            raise ValueError("SSH credential requires a username")
        password = credential.get("password")
        private_key = credential.get("private_key")
        if bool(password) == bool(private_key):
            raise ValueError(
                "SSH credential requires exactly one of password or private_key"
            )

        client_keys: list[Any] = []
        if private_key:
            try:
                client_keys = [
                    asyncssh.import_private_key(
                        private_key,
                        passphrase=credential.get("private_key_passphrase"),
                    )
                ]
            except Exception as exc:
                raise ValueError("SSH private key could not be loaded") from exc

        try:
            return await asyncio.wait_for(
                self._connect_and_run(
                    asyncssh=asyncssh,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    client_keys=client_keys,
                    command=command,
                    timeout_seconds=timeout_seconds,
                ),
                timeout=timeout_seconds,
            )
        except TimeoutError as exc:
            raise RuntimeError("SSH connection or command execution timed out") from exc

    async def _connect_and_run(
        self,
        *,
        asyncssh: Any,
        host: str,
        port: int,
        username: str,
        password: str | None,
        client_keys: list[Any],
        command: str,
        timeout_seconds: int,
    ) -> str:
        try:
            connection = await asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                client_keys=client_keys,
                agent_path=None,
                kbdint_auth=False,
                known_hosts=self.known_hosts_file,
                connect_timeout=timeout_seconds,
                login_timeout=timeout_seconds,
            )
        except Exception as exc:
            raise RuntimeError(
                "SSH connection or host-key verification failed"
            ) from exc
        try:
            try:
                result = await connection.run(command, check=False)
            except Exception as exc:
                raise RuntimeError("SSH command execution failed") from exc
        finally:
            connection.close()
            await connection.wait_closed()

        exit_status = getattr(result, "exit_status", None)
        if exit_status != 0:
            raise RuntimeError(
                f"SSH command failed with exit status {exit_status!r}"
            )
        stdout = getattr(result, "stdout", None)
        if not isinstance(stdout, str):
            raise RuntimeError("SSH command returned an invalid output type")
        return stdout
