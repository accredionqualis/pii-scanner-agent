"""
KnightGuard GRC — Verbose Logger
Controls debug output across all agent modules.
"""
import time
from datetime import datetime

VERBOSE = False

def set_verbose(v: bool):
    global VERBOSE
    VERBOSE = v

def vprint(*args, **kwargs):
    """Print only if verbose mode is on."""
    if VERBOSE:
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        print(f"  [{ts}]", *args, **kwargs)

def vprint_always(*args, **kwargs):
    """Always print — used for important progress."""
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    print(f"  [{ts}]", *args, **kwargs)
