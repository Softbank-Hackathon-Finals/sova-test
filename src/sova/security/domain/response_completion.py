"""Compatibility alias; canonical implementation is sova_security.domain.response_completion."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova_security.domain.response_completion')
