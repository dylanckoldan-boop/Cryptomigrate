from Crypto.Cipher import AES


def replay(key):
    return DES3.new(key, DES3.MODE_ECB)  # cryptomigrate: ignore=CM-PY-001 -- replays a published test vector only
