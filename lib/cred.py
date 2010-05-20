import binascii, hashlib, time

from twisted.application.service import IService, Service

from twisted.cred.error import LoginFailed, UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker

from twisted.internet.defer import inlineCallbacks, returnValue

from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.python.randbytes import secureRandom

from twisted.web.iweb import ICredentialFactory

from zope.interface import Interface, Attribute, implements

from jersey.inet import IP
from jersey.auth.service import IPublicKeyService



class IPrivateKey(Interface):
    """Based on twisted.cred.credentials.ISSHPrivateKey"""
    username = Attribute("Credential's username.")
    client = Attribute("Client IP")
    data = Attribute("Signed data")
    signature = Attribute("The signed data.")


class PrivateKey(object):
    implements(IPrivateKey)

    def __init__(self, username, client, data, signature):
        self.username = username
        self.client = client
        self.data = data
        self.signature = signature



class JerseyChecker(object):
    """Based on twisted.conch.checkers.SSHPublicKeyDatabase.
    """
    implements(ICredentialsChecker)

    credentialInterfaces = (IPrivateKey, )

    def __init__(self, keyService):
        self.svc = keyService


    @staticmethod
    def UnauthorizedLogin(msg="Unauthorized login credentials"):
        return UnauthorizedLogin(msg)


    @inlineCallbacks
    def requestAvatarId(self, credentials):
        log.msg("{0} is requesting an avatar.".format(credentials.username))
        userKeys = yield self.svc.getPublicKeys(credentials.username)

        for key in userKeys:
            if key.verify(credentials.signature, credentials.data):
                returnValue(credentials.username)

        raise self.UnauthorizedLogin("Invalid signature.")


registerAdapter(JerseyChecker, IPublicKeyService, ICredentialsChecker)



class PubKeyCredentialFactory(object):
    implements(ICredentialFactory)

    scheme = "COM.YAHOO.OPS.JERSEY.CRED"

    randLength = 32
    sessionLength = 5*60  # 5 minutes
    digestAlgorithm = "sha256"


    def __init__(self, realmName):
        self.realmName = realmName
        self._secret = secureRandom(self.randLength)


    def getChallenge(self, request):
        seed = self._generateSeed()
        challenge = self._generateChallenge(seed, request)
        return {
            "realm": self.realmName,
            "challenge": challenge,
            }


    def decode(self, response, request):
        auth = self._parseAuth(response)

        try:
            self._verifyChallenge(auth["challenge"], request)
            creds = self._buildCredentials(auth, request)
        except KeyError, ke:
            raise LoginFailed("{0!r} not in authorization.".format(*ke.args))

        return creds


    @property
    def _now(self):
        return int(time.time())


    def _generateSeed(self):
        return secureRandom(self.randLength).encode("hex")

    def _generateChallenge(self, seed, request):
        client = request.getClientIP() or "0.0.0.0"

        raw = "{0.realmName};{1};{2};{0._now}".format(self, seed, client)
        encoded = raw.encode("base64").replace("\n", "")

        key =  "{0};{1}".format(raw, self._secret)
        signed = hashlib.new(self.digestAlgorithm, key).hexdigest()

        return ";".join((signed, encoded, seed))


    def _verifyChallenge(self, challenge, request):
        client = request.getClientIP() or "0.0.0.0"
        try:
            signature, encoded, seed = challenge.split(";", 2)
        except ValueError:
            raise LoginFailed("Invalid challenge value.")

        raw = encoded.decode("base64")

        key = "{0};{1}".format(raw, self._secret)
        signed = hashlib.new(self.digestAlgorithm, key).hexdigest()
        if signed != signature:
            raise LoginFailed("Invalid challenge value.")

        pfx = "{0.realmName};{1};{2};".format(self, seed, client)
        if not raw.startswith(pfx):
            raise LoginFailed("Invalid challenge value.")

        t = int(raw[len(pfx):])
        if t + self.sessionLength < self._now:
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
        log.msg("Building credentials for: {0!r}".format(auth))
        if not auth["username"]:
            raise LoginFailed("Invalid username.")

        client = IP(request.getClientIP() or '0.0.0.0')
        data = str("{0[username]};{0[realm]};{0[challenge]}").format(auth)
        sig = auth["signature"].decode("base64")
        creds = PrivateKey(auth["username"], client, data, sig)

        return creds



