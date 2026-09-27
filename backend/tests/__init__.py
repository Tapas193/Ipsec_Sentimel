"""Backend test suite package.

This file must exist so pytest's default ``prepend`` import mode puts the
``backend/`` directory on ``sys.path``. Without it pytest treats each test
file as a top-level module and the shared fixture module
``tests.synthetic_pcap`` cannot be imported.
"""
