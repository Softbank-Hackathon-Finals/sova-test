"""Compatibility alias; implementation is in sova.security.application.protection_projection."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.application.protection_projection')
