import binascii, time
from hashlib import sha512

from twisted.application.service import IService, Service

from twisted.cred.error import LoginFailed, UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker

from twisted.internet.defer import inlineCallbacks, returnValue

from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.python.randbytes import secureRandom

from twisted.web.iweb import ICredentialFactory

from zope.interface import Interface, Attribute, implements

from jersey.ip import IP
from jersey.auth.service import IPublicKeyService



class IPrivateKey(Interface):
    """Based on twisted.cred.credentials.ISSHPrivateKey"""
    username = Attribute("Credential's username.")
    client = Attribute("Client IP")
    blob = Attribute("The publc key blob as sent by the client.")
    data = Attribute("Signed data")
    signature = Attribute("The signed data.")


class PrivateKey(object):
    implements(IPrivateKey)

    def __init__(self, username, client, blob, data, signature):
        self.username = username
        self.client = client
        self.blob = blob
        self.data = data
        self.signature = signature



class JerseyChecker(object):
    """Based on twisted.conch.checkers.SSHPublicKeyDatabase.
    """
    implements(ICredentialsChecker)

    credentialsInterfaces = (IPrivateKey, )

    def __init__(self, keyService):
        self.svc = keyService


    @staticmethod
    def UnauthorizedLogin(msg="Unauthorized login credentials"):
        return UnauthorizedLogin(msg)


    def getPublicKey(self, credentials):
        try:
            userKeys = yield self.svc.getPublicKeys(credentials.username)
        except KeyError:
            raise self.UnauthorizedLogin()

        keyFound = False
        while (not keyFound) and userKeys:
            key = userKeys.pop()
            keyFound = bool(key.blob() == credentials.blob)

        if not keyFound:
            assert len(userKeys) == 0
            raise self.UnauthorizedLogin()

        returnValue(key)


    @inlineCallbacks
    def requestAvatarId(self, credentials):
        key = yield self.getPublicKey(credentials)
        
        if not key.verify(credentials.signature, credentials.data):
            raise self.UnauthorizedLogin()

        returnValue(credentials.username)


registerAdapter(JerseyChecker, IPublicKeyService, ICredentialsChecker)



class JerseyCredentialFactory(object):
    implements(ICredentialFactory)

    scheme = "JERSEY-AUTH"

    RAND_LEN = 32
    SESSION_LENGTH = 5*60  # 5 minutes


    def __init__(self, realmName):
        self.realmName = realmName
        self._secret = secureRandom(self.RAND_LEN)


    def getChallenge(self, request):
        nonce = self._generateNonce()
        signature = self._buildOpaque(nonce, request)

        return {
            "realm": self.realmName,
            "allowed-methods": "publickey",
            "nonce": nonce,
            "opaque": signature,
            }


    @property
    def _now(self):
        return int(time.time())

    def _generateNonce(self):
        return secureRandom(self.RAND_LEN).encode('hex')


    def _buildOpaque(self, nonce, request):
        client = request.getClientIP() or '0.0.0.0'
        raw = "{0};{1};{2}".format(nonce, client, self._now)
        signed = sha512("{0};{1}".format(raw, self._secret)).hexdigest()
        encoded = raw.encode('base64').replace("\n", "")
        return "{0}-{1}".format(signed, encoded)


    def _verifyOpaque(self, opaque, nonce, request):
        client = request.getClientIP() or "0.0.0.0"
        try:
            signed, encoded = opaque.split("-")
        except ValueError:
            raise LoginFailed("Invalid opaque value.")

        raw = encoded.decode("base64")
        reSigned = sha512("{0};{1}".format(raw, self._secret)).hexdigest()
        if signed != reSigned:
            raise LoginFailed("Invalid opaque value.")

        pfx = "{0};{1};".format(nonce, client)
        if not raw.startswith(pfx):
            raise LoginFailed("Invalid opaque value.")

        t = int(raw[len(pfx):])
        if t + self.SESSION_LENGTH < self._now:
            raise LoginFailed("Session expired.")

        return True


    def _parseAuth(self, response):
        def unQuote(s):
            if s and (s[0] in "\"\'") and (s[0] == s[-1]):
                s = s[1:-1]
            return s

        auth = dict()
        log.msg("Parsing response: {0!r}".format(response))
        for segment in response.replace("\n", " ").split(","):
            log.msg("Parsing segment: {0!r}".format(segment))
            key, val = [s.strip() for s in segment.split("=", 1)]
            auth[key] = unQuote(val)

        return auth


    def _buildCredentials(self, auth, request):
        if not auth["username"]:
            raise LoginFailed("Invalid username.")

        if auth["method"] == "publickey":
            client = IP(request.getClientIP() or '0.0.0.0')
            blob = auth["blob"].decode("base64")
            data = str("{0[username]};{1};{0[realm]};{0[nonce]};{0[opaque]};{2}"
                       ).format(auth, client, blob, self)
            sig = auth["signature"].decode("base64")
            creds = PrivateKey(auth["username"], client, blob, data, sig)

        else:
            e = "Unexpected authentication method: {0[method]}".format(auth)
            raise LoginFailed(e)

        return creds


    def decode(self, response, request):
        auth = self._parseAuth(response)
        client = request.getClientIP() or "0.0.0.0"

        try:
            self._verifyOpaque(auth["opaque"], auth["nonce"], request)
            creds = self._buildCredentials(auth, request)

        except KeyError, ke:
            raise LoginFailed("{0!r} not in authorization.".format(*ke.args))

        return creds



