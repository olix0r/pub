import os
from hashlib import sha512

from twisted.cred.error import LoginFailed
from twisted.python import log
from twisted.python.filepath import FilePath
from twisted.internet.address import IPv4Address
from twisted.trial import util
from twisted.trial.unittest import TestCase
from twisted.web.iweb import ICredentialFactory
from twisted.web.test.test_httpauth import RequestMixin

from zope.interface.verify import verifyObject

from jersey.cred.cred import IPrivateKey, PubKeyCredentialFactory



class FakeCredentialFactory(PubKeyCredentialFactory):
    """
    A Fake Digest Credential Factory that generates a predictable
    seed and time.
    """

    def __init__(self, *args, **kwargs):
        super(FakeCredentialFactory, self).__init__(*args, **kwargs)
        self._secret = "0"


    def _generateSeed(self):
        """Generate a static seed"""
        return "178288758716122392881254770685"


    @property
    def _now(self):
        """Return a stable time"""
        return 0




class JerseyAuthTests(RequestMixin, TestCase):

    suppress = [
        util.suppress(module="Crypto.Hash", category=DeprecationWarning),
        ]


    def setUp(self):
        """
        Create a PubKeyCredentialFactory for testing
        """
        from twisted.conch.ssh.keys import Key

        self.username = "antelope"

        testDir, _f = os.path.split(__file__)
        kd = FilePath(os.path.join(testDir, "animals"))
        self.assertTrue(kd.isdir(), "No priv key dir: {0.path}".format(kd))

        class KeyPair(object):
            def __init__(self, priv, pub):
                self.priv = priv
                self.pub = pub
        self.keys = dict()
        for animal in ("antelope", "monkey"):
            self.keys[animal] = KeyPair(
                Key.fromFile(kd.child(animal).path),
                Key.fromFile(kd.child(animal+".pub").path),
                )

        self.clientAddress = IPv4Address('TCP', '10.2.3.4', 43125)
        self.request = self.makeRequest("GET", self.clientAddress)

        self.realm = "animals@zoo.test"
        self.credentialFactory = PubKeyCredentialFactory(self.realm)


    def assertChallengeOK(self, request):
        challenge = self.credentialFactory.getChallenge(request)

        self.assertEquals(challenge["realm"], self.realm)
        self.assertIn("challenge", challenge)

        for v in challenge.values():
            self.assertNotIn("\n", v)

        return challenge


    def test_interface(self):
        """
        L{PubKeyCredentialFactory} implements L{ICredentialFactory}.
        """
        self.assertTrue(
            verifyObject(ICredentialFactory, self.credentialFactory))


    def test_getChallenge(self):
        """
        The challenge issued by L{PubKeyCredentialFactory.getChallenge} must
        include C{'realm'} and C{'challenge'} keys.  The values for the
        C{'realm'} key must match the value supplied to the factory's
        initializer.  None of the values may have newlines in them.
        """
        self.assertChallengeOK(self.request)


    def test_getChallengeWithoutClientIP(self):
        """
        L{PubKeyCredentialFactory.getChallenge} can issue a challenge even if
        the L{Request} it is passed returns C{None} from C{getClientIP}.
        """
        request = self.makeRequest("GET", None)
        self.assertChallengeOK(request)


    def test_responseWithoutClientIP(self):
        """
        L{PubKeyCredentialFactory.decode} accepts a digest challenge response
        even if the client address it is passed is C{None}.
        """
        req = self.makeRequest()
        c = self.credentialFactory.getChallenge(req)
        auth = self.buildAuth(challenge=c["challenge"])
        auth["signature"] = self.signAuth(auth, req)
        response = self.formatResponse(**auth)

        creds = self.credentialFactory.decode(response, req)
        self.assertSignature(creds)


    def test_multiResponse(self):
        """
        L{PubKeyCredentialFactory.decode} handles multiple responses to a
        single challenge.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(challenge=c["challenge"])
        auth["signature"] = self.signAuth(auth, self.request)
        response = self.formatResponse(**auth)

        creds = self.credentialFactory.decode(response, self.request)
        self.assertSignature(creds)

        creds = self.credentialFactory.decode(response, self.request)
        self.assertSignature(creds)


    def test_noUsername(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} if the response
        has no username field or if the username field is empty.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(challenge=c["challenge"])
        del auth["username"]
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "'username' not in authorization.")


    def test_emtpyUsername(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} if the response
        has no username field or if the username field is empty.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(challenge=c["challenge"])
        auth["username"] = ""
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "Invalid username.")


    def test_noChallenge(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} if the response
        has no challenge.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth()
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "'challenge' not in authorization.")


    def test_checkSignature(self):
        """
        L{PubKeyCredentialFactory.decode} returns an L{IUsernameDigestHash}
        provider which can verify a hash of the form 'username:realm:password'.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(challenge=c["challenge"])
        auth["signature"] = self.signAuth(auth, self.request)
        response = self.formatResponse(**auth)

        creds = self.credentialFactory.decode(response, self.request)

        try:
            verifyObject(IPrivateKey, creds)
        except:
            err = "{0.__class__.__name__} is not a private key".format(creds)
            self.fail(err)

        # Verify this signature with antelope's key.. It should pass.
        self.assertSignature(creds)

        # Try to verify this signature with monkey's key.. It should fail.
        badKey = self.keys["monkey"].pub
        #self.assertNotEquals(badKey.blob(), creds.blob)
        self.assertFalse(badKey.verify(creds.signature, creds.data))


    def test_invalidChallenge(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} when the opaque
        value does not contain all the required parts.
        """
        credentialFactory = FakeCredentialFactory(self.realm)
        c = self.credentialFactory.getChallenge(self.request)
        seed = self.getSeedFromChallenge(c["challenge"])
        client = self.request.getClientIP() or "0.0.0.0"

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, 'badChallenge', self.request)
        self.assertEqual(str(exc), "Invalid challenge value.")

        badData = "realm;{0};clientip;time".format(seed).encode("base64"
                ).replace("\n", "")
        badChallenge = "notasig-{1}-{0}".format(seed, badData)

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, badChallenge, self.request)
        self.assertEqual(str(exc), 'Invalid challenge value.')


    def test_badSeed(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} when the given
        seed from the response does not match the seed encoded in the opaque.
        """
        credentialFactory = FakeCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)

        badSeed = "1234567890"
        parts = c["challenge"].split(";", 2)
        badChallenge = ";".join(parts[0:2] + [badSeed,])

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, badChallenge, self.request)
        self.assertEqual(str(exc), "Invalid challenge value.")

        badChallenge = ";".join(parts[0:2] + ["",])
        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, badChallenge, self.request)
        self.assertEqual(str(exc), "Invalid challenge value.")


    def test_incompatibleClientIP(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} when the
        request comes from a client IP other than what is encoded in the
        opaque.
        """
        credentialFactory = FakeCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)

        badAddress = IPv4Address("TCP", "10.0.0.1", 43210)
        # Sanity check
        self.assertNotEqual(self.request.getClientIP(), badAddress.host)

        badRequest = self.makeRequest("GET", badAddress)
        seed = self.getSeedFromChallenge(c["challenge"])
        badChallenge = credentialFactory._generateChallenge(seed, badRequest)

        self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, badChallenge, self.request)


    def test_oldChallenge(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} when the given
        opaque is older than C{PubKeyCredentialFactory.CHALLENGE_LIFETIME_SECS}
        """
        credentialFactory = FakeCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)
        seed = self.getSeedFromChallenge(c["challenge"])
        client = self.clientAddress.host

        oldTime = "-137876876"
        key = "{0.realm};{1};{2};{3}".format(self, seed, client, oldTime)
        digest = sha512(key + credentialFactory._secret).hexdigest()
        ekey = key.encode("base64").replace("\n", "")
        oldChallenge = "{0}-{1}-{2}".format(digest, ekey, seed)

        self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, oldChallenge, self.request)


    def test_mismatchedChallengeChecksum(self):
        """
        L{PubKeyCredentialFactory.decode} raises L{LoginFailed} when the opaque
        checksum fails verification.
        """
        credentialFactory = FakeCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)
        client = self.clientAddress.host
        seed = self.getSeedFromChallenge(c["challenge"])
        time = '0'

        key = "{0.realm};{1};{2};{3}".format(self, seed, client, time)
        digest = sha512(key + "this is not the right pkey").hexdigest()
        eKey = key.encode("base64").replace("\n", "")
        badChallenge = ";".join((digest, eKey, seed))

        self.assertRaises(LoginFailed,
            credentialFactory._verifyChallenge, badChallenge, self.request)


    def buildAuth(self, **kw):
        if 'username' not in kw:
            kw['username'] = self.username
        if 'realm' not in kw:
            kw['realm'] = self.realm

        privKey = kw.get("privKey", self.keys["antelope"].priv)

        return kw


    def signAuth(self, auth, request):
        """
        Calculate the response for the given challenge
        """
        data = str("{0[username]};{0[realm]};{0[challenge]}"
                   ).format(auth)

        kp = self.keys[auth["username"]]
        signature = kp.priv.sign(data)
        self.assertTrue(kp.pub.verify(signature, data))

        return signature.encode("base64").replace("\n", "")


    def assertSignature(self, creds):
        key = self.keys[creds.username].pub
        self.assertTrue(key.verify(creds.signature, creds.data))


    def formatResponse(self, quotes=True, **kw):
        quote = '"' if quotes is True else str()
        return ', '.join([
                "{0}={2}{1}{2}".format(k, v, quote)
                for (k, v) in kw.iteritems()
                if v is not None])


    def getSeedFromChallenge(self, challenge):
        return challenge.split(";", 2)[2]


