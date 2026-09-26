"""Shared test setup.

The HTTP parser's "retain credential values" switch is a module-level global
(`netlab.analyze.http.set_retain_sensitive`). One test turning harvesting on --
or a persisted config that has it on -- must not leak into another test's
privacy assertion, so it is reset to the redacted default before every test.
A test that needs it on turns it on itself.
"""

import pytest


@pytest.fixture(autouse=True)
def _reset_retain_sensitive():
    try:
        from netlab.analyze import http as httpmod
        httpmod.set_retain_sensitive(False)
    except Exception:
        pass
    yield
    try:
        from netlab.analyze import http as httpmod
        httpmod.set_retain_sensitive(False)
    except Exception:
        pass
