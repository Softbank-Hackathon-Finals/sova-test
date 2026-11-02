"""Compatibility alias; canonical implementation is sova_security.adapters.postgres_signed_evidence."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova_security.adapters.postgres_signed_evidence')
