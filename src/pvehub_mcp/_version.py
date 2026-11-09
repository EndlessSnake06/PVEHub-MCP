"""Single source for the runtime package version.

``pyproject.toml`` stays the packaging source of truth; ``tests/test_packaging_assets.py``
pins the two together so a release cannot ship with a stale runtime version. Kept in a
dependency-free module so both ``server`` and ``clients.base`` can import it without a
circular import through the package ``__init__``.
"""

__version__ = "0.1.3"
