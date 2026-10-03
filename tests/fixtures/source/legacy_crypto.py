from Crypto.Cipher import DES3
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
import pyDes

KEY = "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"


def legacy(key, iv, data):
    c = DES3.new(key, DES3.MODE_CBC, iv)
    k = pyDes.triple_des(key, pyDes.CBC, iv)
    return c.encrypt(data), k
