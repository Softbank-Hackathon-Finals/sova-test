"""Actual-cluster workload-response runner, separate from shared production.

Topologies: `local` (every side on the local RKE2 VM) and `hybrid-aws` (source
on a run-owned EKS cluster, target on local RKE2). See
docs/workload-response-runtime.md.
"""
