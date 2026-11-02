"""Compatibility alias; implementation is in sova.security.adapters.postgres_signed_evidence."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.adapters.postgres_signed_evidence')
