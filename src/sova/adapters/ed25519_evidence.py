"""Compatibility alias; implementation is in sova.security.adapters.ed25519_evidence."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.adapters.ed25519_evidence')
