"""Read-only collection; authenticated tenant/environment binding is external."""

from datetime import datetime
from typing import Protocol

from sova.domain.system_graph import SystemGraph


class InventoryReader(Protocol):
    def inspect(self, *, now: datetime) -> SystemGraph: ...
