"""Compatibility alias; canonical implementation is sova_security.application.protection_projection."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova_security.application.protection_projection')
