"""Compatibility alias; canonical implementation is bravo_security.application.signed_evidence."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('bravo_security.application.signed_evidence')
