"""Compatibility alias to the version-one security boundary contract."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('bravo_security.contracts.evidence')
