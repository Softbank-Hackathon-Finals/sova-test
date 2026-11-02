"""Compatibility alias; implementation is in sova.security.adapters.aws_rds_security."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.adapters.aws_rds_security')
