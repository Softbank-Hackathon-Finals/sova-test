"""Trusted runtime injects credentials, authentication/authorization and clock."""

from typing import Protocol


class KubernetesReadTransport(Protocol):
    @property
    def registration_digest(self) -> str: ...

    def get(self, path: str, query: dict[str, str], *, timeout: float) -> dict: ...
