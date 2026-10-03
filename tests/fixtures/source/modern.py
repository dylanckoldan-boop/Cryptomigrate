from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DESCRIPTION = "replaces the old DES implementation"


def seal(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
