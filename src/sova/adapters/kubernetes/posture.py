"""Compatibility alias; implementation is in sova.security.adapters.kubernetes.posture."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.adapters.kubernetes.posture')
