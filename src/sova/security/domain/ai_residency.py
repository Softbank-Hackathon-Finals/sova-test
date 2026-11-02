"""Compatibility alias; canonical implementation is bravo_security.domain.ai_residency."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('bravo_security.domain.ai_residency')
