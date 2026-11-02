"""Compatibility alias; implementation is in sova.security.ports.security_events."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.ports.security_events')
