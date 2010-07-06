"""
jersey.cred.guard --  PubKey.v1 for twisted.web.
"""


import hashlib, time

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.error import LoginFailed, UnauthorizedLogin
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python.components import registerAdapter
from twisted.python.randbytes import secureRandom
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.iweb import ICredentialFactory

from zope.interface import Interface, Attribute, implements

from jersey import log
from jersey.inet import IP
from jersey.cred.service import IPublicKeyService



class ISignedAuthorization(Interface):
    """Based on twisted.cred.credentials.ISSHPrivateKey"""

    identifier = Attribute("Credential's entity")
    client = Attribute("Client IP")
    data = Attribute("Signed data")
    signature = Attribute("The signed data")



class SignedAuthorization(object):
    implements(ISignedAuthorization)

    def __init__(self, identifier, client, data, signature):
        self.identifier = identifier
        self.client = IP(client)
        self.data = data
        self.signature = signature



class JerseyChecker(object):
    """Based on twisted.conch.checkers.SSHPublicKeyDatabase.
    """
    implements(ICredentialsChecker)

    credentialInterfaces = (ISignedAuthorization, )

    def __init__(self, keyService):
        self.svc = keyService


    @staticmethod
    def UnauthorizedLogin(msg="Unauthorized login credentials"):
        return UnauthorizedLogin(msg)


    @inlineCallbacks
    def requestAvatarId(self, cred):
        log.debug("{0} is requesting an avatar.".format(cred.identifier))
        try:
            userKeys = yield self.svc.getPublicKeys(cred.identifier)

        except KeyError, ke:
            raise self.UnauthorizedLogin("Invalid user", cred.identifier)

        if not self._verifySignatureByKeys(cred, userKeys):
            raise self.UnauthorizedLogin("Invalid signature")

        returnValue(cred.identifier)


    @staticmethod
    def _verifySignatureByKeys(credentials, keys):
        verified = False
        while len(keys) and not verified:
            key = keys.pop()
            verified = key.verify(credentials.signature, credentials.data)
        return verified


registerAdapter(JerseyChecker, IPublicKeyService, ICredentialsChecker)



class PubKeyCredentialFactory(object):
    """Generates PubKey.v1 WWW-Authenticate challenge headers and builds
    SignedAuthorization credentials from PubKey.v1 Authrorization headers.
    """
    implements(ICredentialFactory)

    scheme = "PubKey.v1"

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
        challenge = self.generateChallenge(request)
        return {"realm": self.realm, "challenge": challenge,}


    def decode(self, response, request):
        """Decode an authorization response into a SignedAuthorization."""
        log.debug("Decoding authorization.")
        auth = self._parseAuth(response)
        try:
            self._verifyChallenge(auth["challenge"], request)
            creds = self.buildCredentials(auth, request)
        except KeyError, ke:
            raise LoginFailed("{0!r} not in authorization".format(*ke.args))
        except LoginFailed, lf:
            log.warn(lf)
            raise
        log.debug("Decoded credentials: {0}".format(creds))
        return creds


    _authFmt = "{a[id]}{s}{a[realm]}{s}{a[challenge]}"

    def buildCredentials(self, auth, request):
        log.debug("Building credentials from {0!r}".format(auth))
        if not auth["id"]:
            raise LoginFailed("No identifier")

        client = request.getClientIP() or '0.0.0.0'
        data = self._authFmt.format(a=auth, s=self.sep)
        sig = auth["signature"].decode("base64")
        creds = SignedAuthorization(auth["id"], client, data, sig)

        return creds



    @staticmethod
    def _getTime():
        return int(time.time())


    def _generateSecret(self):
        return secureRandom(self.randLength)

    def _generateSeed(self):
        return self._generateSecret().encode("base64").replace("\n", "")


    _challengeFmt = "{realm}{sep}{client}{sep}{time}{sep}{seed}"

    def generateChallenge(self, request):
        """Generate a challenge for the request.
        
        The client is expected to sign this challenge string such
        """
        client = request.getClientIP() or "0.0.0.0"
        seed = self._generateSeed()
        now = self._getTime()
        raw = self._challengeFmt.format(realm=self.realm, client=client,
                time=now, seed=seed, sep=self.sep)
        encoded = raw.encode("base64").replace("\n", "")
        signed = self._sign(raw).encode("base64").replace("\n", "")
        return self.sep.join((signed, encoded))


    def _verifyChallenge(self, challenge, request):
        """Verify a challenge as returned from _generateChallenge.
        """
        log.debug("Verifying challenge: {0}".format(challenge))
        try:
            signature, encoded = challenge.split(self.sep)
            raw = encoded.decode("base64")
            realm, clientIP, sigTime, seed = raw.split(self.sep)
        except ValueError:
            raise LoginFailed("Invalid challenge value")
        if not self._verify(signature, raw):
            raise LoginFailed("Invalid signature")
        if realm != self.realm:
            raise LoginFailed("Incorrect realm")
        if self._timeExpired(sigTime):
            raise LoginFailed("Session expired")
        if clientIP != (request.getClientIP() or "0.0.0.0"):
            raise LoginFailed("Incorrect client")
        return True


    def _digest(self, value):
        return hashlib.new(self.digestAlgorithm, value).digest()


    # You know, it would be interesting if the service could have a KeyPair so
    # to that it could *encrypt* the challenge to itself.  Furthermore, it's
    # possible that the server could generate a signature for this challenge,
    # and the client then has the ability to verify the server's challenge.

    def _sign(self, value):
        return self._digest("{1}{0.sep}{0._secret}".format(self, value))

    def _verify(self, signature, value):
        return bool(self._sign(value) == signature.decode("base64"))


    def _timeExpired(self, t):
        return bool(int(t) + self.sessionLength < self._getTime())


    def _parseAuth(self, response):
        auth = dict()
        for segment in response.replace("\n", " ").split(","):
            key, val = [s.strip() for s in segment.split("=", 1)]
            auth[key] = self._unQuote(val)
        return auth

    @staticmethod
    def _unQuote(s):
        if s and (s[0] in "\"\'") and (s[0] == s[-1]):
            s = s[1:-1]
        return s



class Guard(HTTPAuthSessionWrapper):

    def _login(self, creds):
        log.info("Logging in: {0!r}".format(creds))
        return HTTPAuthSessionWrapper._login(self, creds)


    def _selectParseHeader(self, header):
        """Find an authentication scheme in a case-insensitive way."""
        log.debug("Finding an authenticator for {0}".format(header))
        scheme, elements = header.split(' ', 1)
        for fact in self._credentialFactories:
            if fact.scheme.lower() == scheme.lower():
                log.debug("Found an authenticator: {0}".format(fact))
                return (fact, elements)

        log.warn("No matching authenticator found for {0}".format(scheme))
        return (None, None)


