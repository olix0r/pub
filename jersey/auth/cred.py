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
    algorithm = Attribute("The algorithm name for the blob.")
    blob = Attribute("The publc key blob as sent by the client.")
    data = Attribute("The data the signature was made from.")
    signature = Attribute("The signed data.")


class PrivateKey(object):

    def __init__(self, username, client, algorithm, blob, signature):
        self.username = username
        self.client = client
        self.algorithm = algorithm
        self.blob = blob
        self.signature = signature



class JerseyChecker(object):
    """Based on twisted.conch.checkers.SSHPublicKeyDatabase.
    """
    implements(ICredentialsChecker)

    credentialsInterfaces = (IPrivateKey, )

    def __init__(self, keyService):
        self.svc = keyService


    @staticmethod
    def UnauthorizedLogin():
        return UnauthorizedLogin("Unauthorized login credentials")


    def getPublicKey(self, credentials):
        user, algName = credentials.user, credentials.algName
        try:
            userKeys = yield self.svc.getPublicKeys(user, algName)
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
        key.verify(credentials.signature, credentials.sigData)
        returnValue(credentials.user)


registerAdapter(JerseyChecker, IPublicKeyService, ICredentialsChecker)



class JerseyCredentialFactory(object):
    implements(ICredentialFactory)

    scheme = "JERSEY-AUTH"

    RAND_LEN = 32
    SESSION_LENGTH = 5*60  # 5 minutes


    def __init__(self, realmName):
        self.realmName = realmName
        self.__secret = secureRandom(self.RAND_LEN)


    def getChallenge(self, request):
        nonce = self._buildNonce()
        client = request.getClientIP() or '0.0.0.0'
        signature = self._buildOpaque(nonce, client)

        return {
            "realm": self.realmName,
            "allowed-methods": "publickey",
            "nonce": nonce,
            "opaque": signature,
            }


    @property
    def _time(self):
        time.time()

    def _buildNonce(self):
        return secureRandom(self.RAND_LEN).encode('hex')

    def _buildOpaque(self, nonce, client):
        now = int(time.time())
        raw = "{0};{1};{2}".format(nonce, client, now)
        signed = sha512("{0};{1}".format(raw, self.__secret)).hexdigest()
        eRaw = raw.encode('base64').replace("\n", "")
        return "{0}-{1}".format(signed, eRaw)


    def _parseAuth(self, responseStr):
        def unQuote(s):
            if s and s[0] in "\"\'" and s[0] == s[-1]:
                s = s[1:-1]
            return s

        auth = dict()
        for parts in responseStr.replace("\n", " ").split(","):
            for segment in parts:
                key, val = [s.strip() for s in segment.split("=", 1)]
                auth[key] = unQuote(val)

        return auth


    def _buildCredentials(self, auth, request):
        if auth["method"] == "publickey":
            client = IP(request.clientIP() or '0.0.0.0')
            data = str("{0[username]};{1};{2};{3.realmName};"
                       "{0[algor]};{0[blob]};{0[uri]}"
                       ).format(auth, client, request.method, self)

            creds = SSHPrivateKey(auth["username"], auth["algor"],
                                  auth["blob"], data, auth["signature"])

        else:
            e = "Unexpected authentication method: {0[method]}".format(auth)
            raise LoginFailed(e)

        return creds


    def decode(self, response, request):
        auth = self._parseAuth(response)
        try:
            return self._buildCredentials(auth, request)

        except KeyError, ke:
            raise LoginFailed("{0!r} not in authorization".format(ke.args))


