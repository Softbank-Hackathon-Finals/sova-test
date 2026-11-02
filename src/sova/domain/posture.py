"""Compatibility alias; implementation is in sova.security.domain.posture."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.domain.posture')
