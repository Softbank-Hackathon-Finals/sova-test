"""Recovery proof authentication is mandatory; there is no self-approved flag."""

from sova.domain.execution import QuiescenceProof
from sova.ports.execution import ExecutionOwnership


class ExecutionRecovery:
    def __init__(self, ownership: ExecutionOwnership, *, authenticate_proof):
        self.ownership, self.authenticate_proof = ownership, authenticate_proof

    def acquire(self, proof: QuiescenceProof, owner_id: str, *, lease_seconds=30):
        self.authenticate_proof(proof)
        return self.ownership.acquire_recovery(
            proof, owner_id, lease_seconds=lease_seconds
        )
