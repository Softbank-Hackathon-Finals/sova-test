"""Compatibility alias; implementation is in sova.security.adapters.postgres_security_events."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.adapters.postgres_security_events')
