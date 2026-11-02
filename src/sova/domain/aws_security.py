"""Compatibility alias; implementation is in sova.security.domain.aws_security."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.domain.aws_security')
