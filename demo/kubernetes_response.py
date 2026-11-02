"""Compatibility alias for the owned qualification adapter."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.qualification.kubernetes_response')
