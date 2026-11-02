"""Compatibility alias; canonical implementation is sova_security.adapters.aws_rds_security."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova_security.adapters.aws_rds_security')
