"""Compatibility alias; implementation is in sova.security.adapters.response_completion_codec."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module('sova.security.adapters.response_completion_codec')
