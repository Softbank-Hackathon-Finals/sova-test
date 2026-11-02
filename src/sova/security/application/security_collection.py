"""Compatibility alias; canonical implementation is bravo_security.application.security_collection."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('bravo_security.application.security_collection')
