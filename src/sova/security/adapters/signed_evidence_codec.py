"""Compatibility alias; canonical implementation is bravo_security.adapters.signed_evidence_codec."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('bravo_security.adapters.signed_evidence_codec')
