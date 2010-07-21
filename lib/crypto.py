import re, sys
from hashlib import md5

from Crypto import Util
from Crypto.Cipher import AES, Blowfish, DES3
from Crypto.PublicKey import RSA, DSA
from pyasn1.codec.der import decoder as DERDecoder
from twisted.conch.ssh.keys import (
        BadKeyError, EncryptedKeyError,
        Key as _Key)
from twisted.conch.ssh import common
from twisted.conch.ssh.transport import _DummyCipher
from twisted.python.util import InsensitiveDict

from jersey import log


class Key(_Key):


    _idLen = 8

    @property
    def id(self):
        return self.fingerprint().replace(":", "")[-self._idLen:].upper()


    def encrypt(self, plaintext):
        s = self.keyObject.size() / 8
        ciphertext = ""
        while plaintext:
            d, plaintext = plaintext[:s], plaintext[s:]
            ciphertext += self.keyObject.encrypt(d, None)[0]
        return ciphertext


    def decrypt(self, ciphertext):
        s = self.keyObject.size() / 8 + 1
        plaintext = ""
        while ciphertext:
            e, ciphertext = ciphertext[:s], ciphertext[s:]
            plaintext += self.keyObject.decrypt(e)
        return plaintext


    def public(self):
        return self.__class__(self.keyObject.publickey())

