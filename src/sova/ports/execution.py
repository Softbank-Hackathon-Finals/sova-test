from typing import Protocol

from sova.domain.execution import ExecutionLease, QuiescenceProof


class ExecutionBusy(RuntimeError):
    pass


class RecoveryRequired(RuntimeError):
    pass


class ExecutionOwnership(Protocol):
    tenant_id: str

    def acquire(
        self,
        application_id: str,
        operation_id: str,
        owner_id: str,
        *,
        lease_seconds: int = 30,
    ) -> ExecutionLease: ...
    def acquire_recovery(
        self, proof: QuiescenceProof, owner_id: str, *, lease_seconds: int = 30
    ) -> ExecutionLease: ...
    def renew(
        self, lease: ExecutionLease, *, lease_seconds: int = 30
    ) -> ExecutionLease: ...
    def release(self, lease: ExecutionLease) -> None: ...
