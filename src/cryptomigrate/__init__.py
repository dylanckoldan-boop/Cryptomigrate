"""cryptomigrate - SDLC-driven toolkit for migrating DES / Triple-DES (TDEA) to AES-GCM.

Library entry point for applications during the dual-mode transition::

    from cryptomigrate import CryptoService
    svc = CryptoService.from_config("migration.yaml")
    token = svc.encrypt_text(b"4111111111111111", context="cards.pan#42")
    svc.decrypt(token, context="cards.pan#42")
"""

__version__ = "1.1.0"
__all__ = ["CryptoService", "__version__"]


def __getattr__(name: str):  # lazy import keeps `python -m cryptomigrate --help` fast
    if name == "CryptoService":
        from .crypto.service import CryptoService

        return CryptoService
    raise AttributeError(name)
