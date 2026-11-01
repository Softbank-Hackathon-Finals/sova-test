"""Prepare restrictive Harbor task config, without starting a runner or an agent.

The caller must independently admit/qualify a runner, verify artifact digests,
prepare source/test images, transfer sanitized outputs and enforce residency.
No credentials, arbitrary shell commands or uploaded task config are accepted.
"""

import hashlib
import json

from sova.domain.contracts import canonical_json
from sova.domain.sandbox import SandboxRequest


def prepare_task(request: SandboxRequest, *, now):
    request.require_current(now)
    # Baseline is restrictive even during agent.setup(), not only agent.run().
    config = f"""schema_version = "1.4"

[environment]
docker_image = {json.dumps(request.agent_image)}
network_mode = "no-network"
cpus = 1
memory_mb = 2048
storage_mb = 4096

[agent]
timeout_sec = {request.timeout_seconds}

[verifier]
environment_mode = "separate"
timeout_sec = {request.timeout_seconds}

[verifier.environment]
docker_image = {json.dumps(request.verifier_image)}
network_mode = "no-network"
cpus = 1
memory_mb = 2048
storage_mb = 4096
"""
    binding = {
        "request_id": request.request_id,
        "request_digest": request.fingerprint,
        "scope": {
            k: getattr(request.scope, k)
            for k in ("tenant_id", "application_id", "environment_id", "resource_id")
        },
        "source_digest": request.source_digest,
        "tests_digest": request.tests_digest,
        "config_digest": hashlib.sha256(config.encode()).hexdigest(),
        "valid_until": request.valid_until.isoformat(),
    }
    return {
        "status": "prepared-not-executed",
        "executable": False,
        "binding": binding,
        "binding_digest": hashlib.sha256(canonical_json(binding).encode()).hexdigest(),
        "task_toml": config,
        "requirements": [
            "qualify-provider-isolation-and-network-before-start",
            "verify-source-and-tests-digests-against-images",
            "preinstall-offline-agent-no-model-key-in-guest",
            "independent-verifier-image-must-contain-tests-test.sh",
            "sanitize-and-bind-output-artifacts-before-verifier",
            "external-policy-model-gateway-integration-required-for-ai",
            "independent-approval-and-signing-before-promotion",
        ],
    }
