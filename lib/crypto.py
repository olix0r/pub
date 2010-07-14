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


    _cipherMap = {
        'AES-256-CBC':(AES, 32),
        'AES-192-CBC':(AES, 24),
        'AES-128-CBC':(AES, 16),
        'BLOWFISH-CBC':(Blowfish, 16),
        '3DES-CBC':(DES3, 24),
        'DES-EDE3-CBC':(DES3, 24),
        'NONE':(_DummyCipher, 0),
        }

    _keyTypes = ("RSA", "DSA")

    _privateKeyBeginRE = re.compile(
            "^-----BEGIN ({0}) PRIVATE KEY-----$".format("|".join(_keyTypes)))



    @classmethod
    def _fromString_PRIVATE_OPENSSH(Class, data, passphrase):
        """
        Return a private key object corresponding to this OpenSSH private key
        string.  If the key is encrypted, passphrase MUST be provided.
        Providing a passphrase for an unencrypted key is an error.

        @type data: C{str}
        @type passphrase: C{str}
        @return: a C{Crypto.PublicKey.pubkey.pubkey} object
        @raises BadKeyError: if
            * a passphrase is provided for an unencrypted key
            * a passphrase is not provided for an encrypted key
            * the ASN.1 encoding is incorrect
        """
        kind, headers, encKey = Class._parsePrivateKey(data)

        if headers.get("Proc-Type") == "4,ENCRYPTED":
            if not passphrase:
                raise EncryptedKeyError("encrypted key with no passphrase")
            cipher, iv = Class._parseDekInfo(headers["DEK-Info"])
            keyData = Class._decryptPrivateKey(cipher, iv, passphrase,
                    encKey.decode("base64"))
        else:
            keyData = encKey.decode("base64")

        decodedKey = Class._decodeKey(keyData)
        key = Class._buildKey(kind, decodedKey)

        return key


    @classmethod
    def _parsePrivateKey(Class, data):
        """The format of an OpenSSH private key string is::
            -----BEGIN <key type> PRIVATE KEY-----
            [Proc-Type: 4,ENCRYPTED
            DEK-Info: <cipher>,<initialization value>]
            
            <base64-encoded ASN.1 structure>
            ------END <key type> PRIVATE KEY------
        """
        lines = data.split("\n")
        keyType = Class._parseKeyType(lines)
        headers = Class._parseHeaders(lines)
        keyData = Class._parseKeyData(lines, keyType)
        return keyType, headers, keyData


    @classmethod
    def _parseKeyType(Class, lines):
        keyType = None
        while lines and keyType is None:
            line = lines.pop(0)
            m = Class._privateKeyBeginRE.match(line)
            if m:
                keyType = m.groups()[0]
        if not keyType:
            raise BadKeyError("No private key found.")
        return keyType


    @classmethod
    def _parseHeaders(Class, lines):
        headers = InsensitiveDict()
        moreHeaders = True
        key, val = None, None
        while lines and moreHeaders:
            line = lines.pop(0)
            if line == "":  # end of headers
                moreHeaders = False
                if key and val:  # save header
                    headers[key] = val
                    key, val = None, None
            else:
                if key and val:  # already parsing a header
                    val += line
                else:  # new header
                    try:
                        key, val = line.split(":", 1)
                        val = val.lstrip()
                    except ValueError:
                        lines.insert(0, line)
                        return headers
                if val.endswith("\\"):  # header will be continued
                    val = val[:-1]  # strip trailing escape char
                else:  # save header
                    headers[key] = val
                    key, val = None, None
        return headers


    @classmethod
    def _parseKeyData(Class, lines, keyType):
        endToken = "-----END {0} PRIVATE KEY-----".format(keyType)
        keyData = ""
        moreKey = True
        while lines and moreKey:
            line = lines.pop(0)
            if line == endToken:
                moreKey = False
            else:
                keyData += line
        if moreKey:
            raise BadKeyError("No END delimeter found")
        if not keyData:
            raise BadKeyError("No private key data found")
        return keyData


    @classmethod
    def _buildKey(Class, kind, keyData):
        buildKey = getattr(Class, "_buildPrivateKey_{0}".format(kind))
        return buildKey(keyData)


    @classmethod
    def _buildPrivateKey_RSA(Class, decodedKey):
        """The ASN.1 structure of a RSA key is::
            (0, n, e, d, p, q)
        """
        if len(decodedKey) == 2: # alternate RSA key
            decodedKey = decodedKey[0]
        if len(decodedKey) < 6:
            raise BadKeyError('RSA key failed to decode properly')
        n, e, d, p, q = [long(value) for value in decodedKey[1:6]]
        if p > q: # make p smaller than q
            p, q = q, p
        return Class(RSA.construct((n, e, d, p, q)))

    @classmethod
    def _buildPrivateKey_DSA(Class, decodedKey):
        """The ASN.1 structure of a DSA key is::
            (0, p, q, g, y, x)
        """
        p, q, g, y, x = [long(value) for value in decodedKey[1: 6]]
        if len(decodedKey) < 6:
            raise BadKeyError('DSA key failed to decode properly')
        return Class(DSA.construct((y, g, p, q, x)))


    @classmethod
    def _parseDekInfo(Class, dekInfo):
        cipher, ivData = dekInfo.split(',')
        iv = ivData.decode("hex")
        return cipher, iv


    @classmethod
    def _decryptPrivateKey(Class, cipherName, iv, passphrase, data):
        cipher, keySize = Class._cipherMap[cipherName.upper()]
        decKey = Class._buildDecryptKey(passphrase, iv, keySize)
        c = cipher.new(decKey, cipher.MODE_CBC, iv[:cipher.block_size])
        keyData = c.decrypt(data)
        return Class._trimPadding(keyData)


    @classmethod
    def _trimPadding(Class, keyData):
        removeLen = ord(keyData[-1])
        return keyData[:-removeLen]


    @classmethod
    def _buildDecryptKey(Class, passphrase, iv, keyLen=16, ivLen=8):
        d = md5()
        dk = ""
        while len(dk) < keyLen:
            d.update(passphrase)
            d.update(iv[:ivLen])
            t = d.digest()
            dk += t
            d.update(t)
        return dk[:keyLen]


    @classmethod
    def _decodeKey(self, encoded):
        try:
            return DERDecoder.decode(encoded)[0]
        except Exception, e:
            raise BadKeyError('something wrong with decode')


