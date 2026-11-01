"""Phase identities are distinct from a full migration's operation status."""

from enum import StrEnum


class MigrationPhase(StrEnum):
    PREPARE = "prepare"
    SYNCHRONIZE = "synchronize"
    REHEARSE = "rehearse"
    QUIESCE = "quiesce"
    CUTOVER = "cutover"
    POSTCHECK = "postcheck"
