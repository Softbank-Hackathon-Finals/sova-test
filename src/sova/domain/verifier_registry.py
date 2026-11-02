"""Compatibility alias; implementation is in sova.security.domain.verifier_registry."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.domain.verifier_registry')
