import binascii, hashlib, time

from twisted.application.service import IService, Service

from twisted.cred.error import LoginFailed, UnauthorizedLogin
from twisted.cred.checkers import ICredentialsChecker

from twisted.internet.defer import inlineCallbacks, returnValue

from twisted.python.components import registerAdapter
from twisted.python.randbytes import secureRandom

from twisted.web.iweb import ICredentialFactory

from zope.interface import Interface, Attribute, implements

from jersey import log
from jersey.inet import IP
from jersey.cred.service import IPublicKeyService



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
    def requestAvatarId(self, cred):
        log.debug("{0} is requesting an avatar.".format(cred.username))
        try:
            userKeys = yield self.svc.getPublicKeys(cred.username)

        except KeyError, ke:
            raise self.UnauthorizedLogin("Invalid user", cred.username)

        if not self._verifySignatureByKeys(cred, userKeys):
            raise self.UnauthorizedLogin("Invalid signature")

        returnValue(cred.username)


    @staticmethod
    def _verifySignatureByKeys(credentials, keys):
        verified = False
        while len(keys) and not verified:
            key = keys.pop()
            verified = key.verify(credentials.signature, credentials.data)
        return verified


registerAdapter(JerseyChecker, IPublicKeyService, ICredentialsChecker)



class PubKeyCredentialFactory(object):
    implements(ICredentialFactory)

    scheme = "PubKey/0.1"

    randLength = 32
    sessionLength = 5*60  # 5 minutes
    digestAlgorithm = "sha256"
    sep = ";"

    def __init__(self, realm, secret=None, sessionLength=None,
            digestAlgorithm=None, randLength=None):
        self.realm = realm
        if digestAlgorithm is not None:
            self.digestAlgorithm = digestAlgorithm
        if randLength is not None:
            self.randLength = randLength
        if sessionLength is not None:
            self.sessionLength = sessionLength
        
        if secret is not None:
            self._secret = secret
        else:
            self._secret = self._generateSecret()
            

    def getChallenge(self, request):
        seed = self._generateSeed()
        challenge = self._generateChallenge(seed, request)
        return {
            "realm": self.realm,
            "challenge": challenge,
            }


    def decode(self, response, request):
        log.debug("Decoding authorization.")
        auth = self._parseAuth(response)

        try:
            self._verifyChallenge(auth["challenge"], request)
            creds = self._buildCredentials(auth, request)
        except KeyError, ke:
            raise LoginFailed("{0!r} not in authorization.".format(*ke.args))

        log.debug("Decoded credentials: {0}".format(creds))
        return creds


    @property
    def _now(self):
        return int(time.time())


    def _generateSecret(self):
        return secureRandom(self.randLength)

    def _generateSeed(self):
        return self._generateSecret().encode("hex")

    def _generateChallenge(self, seed, request):
        """Generate a challenge for the request.
        
        The client is expected to sign this challenge string such
        """
        client = request.getClientIP() or "0.0.0.0"

        raw = "{0.realm}{0.sep}{1}{0.sep}{2}{0.sep}{0._now}".format(
                self, seed, client)
        encoded = raw.encode("base64").replace("\n", "")
        log.debug("Generated challenge: {0}".format(encoded))

        signed = self._digest("{1}{0.sep}{0._secret}".format(self, raw))
        log.debug("Generated signature: {0}".format(signed))

        return self.sep.join((signed, encoded, seed))


    def _verifyChallenge(self, challenge, request):
        """Verify a challenge as returned from _generateChallenge.
        """
        log.debug("Decoding challenge: {0}".format(challenge))

        client = request.getClientIP() or "0.0.0.0"

        try:
            signature, encoded, seed = challenge.split(self.sep, 2)
            raw = encoded.decode("base64")
        except ValueError:
            raise LoginFailed("Invalid challenge value.")

        log.debug("Verifying signature={0}\nchallenge={1}".format(signature, raw))

        signedChallenge = self._digest("{1}{0.sep}{0._secret}".format(self, raw))
        if signedChallenge != signature:
            log.warn("Expected signature: {0}".format(signedChallenge))
            raise LoginFailed("Invalid challenge value.")

        expected = "{0.realm}{0.sep}{1}{0.sep}{2}{0.sep}".format(
                self, seed, client)
        if not raw.startswith(expected):
            raise LoginFailed("Invalid challenge value.")

        sigTime = int(raw[len(expected):])
        if sigTime + self.sessionLength < self._now:
            raise LoginFailed("Session expired.")

        return True


    def _digest(self, value):
        return hashlib.new(self.digestAlgorithm, value).hexdigest()


    def _parseAuth(self, response):
        def unQuote(s):
            if s and (s[0] in "\"\'") and (s[0] == s[-1]):
                s = s[1:-1]
            return s

        auth = dict()
        for segment in response.replace("\n", " ").split(","):
            key, val = [s.strip() for s in segment.split("=", 1)]
            auth[key] = unQuote(val)

        return auth


    def _buildCredentials(self, auth, request):
        log.msg("Building credentials for: {0!r}".format(auth))
        if not auth["username"]:
            raise LoginFailed("Invalid username.")

        client = IP(request.getClientIP() or '0.0.0.0')
        data = "{1[username]}{0.sep}{1[realm]}{0.sep}{1[challenge]}".format(
                self, auth)
        sig = auth["signature"].decode("base64")
        creds = PrivateKey(auth["username"], client, data, sig)

        return creds



