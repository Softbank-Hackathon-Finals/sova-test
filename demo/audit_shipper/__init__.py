"""Ship runner evidence to an append-only (Object Lock) bucket and prove it.

Separate from the runner on purpose: the runner never holds the audit write
role, and this shipper never holds cluster or database access. See
docs/workload-response-runtime.md (audit retention).
"""
