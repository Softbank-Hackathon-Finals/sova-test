"""Compatibility alias; canonical implementation is bravo_security.adapters.postgres_protection_parity."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('bravo_security.adapters.postgres_protection_parity')
