"""Compatibility alias; canonical implementation is sova_security.adapters.verifier_registry_codec."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova_security.adapters.verifier_registry_codec')
