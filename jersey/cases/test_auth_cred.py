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

from jersey.auth.cred import IPrivateKey, JerseyCredentialFactory



class FakeJerseyCredentialFactory(JerseyCredentialFactory):
    """
    A Fake Digest Credential Factory that generates a predictable
    nonce and opaque
    """

    def __init__(self, *args, **kwargs):
        super(FakeJerseyCredentialFactory, self).__init__(*args, **kwargs)
        self._secret = "0"


    def _generateNonce(self):
        """Generate a static nonce"""
        return "178288758716122392881254770685"


    @property
    def _now(self):
        """Return a stable time"""
        return 0




class SimpleJerseyAuthTestCase(RequestMixin, TestCase):
    """
    Public key authentication tests which use twisted.web.http.Request.
    """

    suppress = [
        util.suppress(module="Crypto.Hash", category=DeprecationWarning),
        ]

    def setUp(self):
        self.realm = "animals@zoo.example.com"
        self.credentialFactory = JerseyCredentialFactory(self.realm)
        self.request = self.makeRequest()


    def assertChallengeOK(self, request):
        challenge = self.credentialFactory.getChallenge(request)

        self.assertEquals(challenge["allowed-methods"], "publickey")
        self.assertEquals(challenge["realm"], self.realm)
        self.assertIn("nonce", challenge)
        self.assertIn("opaque", challenge)
        for v in challenge.values():
            self.assertNotIn("\n", v)

        return challenge


    def test_decode(self):
        """
        L{digest.JerseyCredentialFactory.decode} calls the C{decode} method on
        L{twisted.cred.digest.JerseyCredentialFactory} with the HTTP method and
        host of the request.
        """
        host = '169.254.0.1'
        method = 'GET'
        done = [False]
        response = object()
        def check(_response, _method, _host):
            self.assertEqual(response, _response)
            self.assertEqual(method, _method)
            self.assertEqual(host, _host)
            done[0] = True

        self.patch(self.credentialFactory.digest, 'decode', check)
        req = self.makeRequest(method, IPv4Address('TCP', host, 81))
        self.credentialFactory.decode(response, req)
        self.assertTrue(done[0])
    test_decode.skip = "TODO"


    def test_interface(self):
        """
        L{JerseyCredentialFactory} implements L{ICredentialFactory}.
        """
        self.assertTrue(
            verifyObject(ICredentialFactory, self.credentialFactory))


    def test_getChallenge(self):
        """
        The challenge issued by L{JerseyCredentialFactory.getChallenge} must
        include C{'qop'}, C{'realm'}, C{'algorithm'}, C{'nonce'}, and
        C{'opaque'} keys.  The values for the C{'realm'} and C{'algorithm'}
        keys must match the values supplied to the factory's initializer.
        None of the values may have newlines in them.
        """
        self.assertChallengeOK(self.request)


    def test_getChallengeWithoutClientIP(self):
        """
        L{JerseyCredentialFactory.getChallenge} can issue a challenge even if
        the L{Request} it is passed returns C{None} from C{getClientIP}.
        """
        request = self.makeRequest("GET", None)
        self.assertChallengeOK(request)



class JerseyAuthTests(RequestMixin, TestCase):

    suppress = [
        util.suppress(module="Crypto.Hash", category=DeprecationWarning),
        ]


    def setUp(self):
        """
        Create a JerseyCredentialFactory for testing
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
                Key.fromFile(kd.child("priv").child(animal).path),
                Key.fromFile(kd.child("pub").child(animal).path),
                )

        self.clientAddress = IPv4Address('TCP', '10.2.3.4', 43125)
        self.request = self.makeRequest("GET", self.clientAddress)

        self.realm = "animals@zoo.test"
        self.credentialFactory = JerseyCredentialFactory(self.realm)


    def test_responseWithoutClientIP(self):
        """
        L{JerseyCredentialFactory.decode} accepts a digest challenge response
        even if the client address it is passed is C{None}.
        """
        req = self.makeRequest()
        c = self.credentialFactory.getChallenge(req)
        auth = self.buildAuth(nonce=c["nonce"], opaque=c["opaque"])
        auth["signature"] = self.signAuth(auth, req)
        response = self.formatResponse(**auth)

        creds = self.credentialFactory.decode(response, req)
        self.assertSignature(creds)


    def test_multiResponse(self):
        """
        L{JerseyCredentialFactory.decode} handles multiple responses to a
        single challenge.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(nonce=c["nonce"], opaque=c["opaque"])
        auth["signature"] = self.signAuth(auth, self.request)
        response = self.formatResponse(**auth)

        creds = self.credentialFactory.decode(response, self.request)
        self.assertSignature(creds)

        creds = self.credentialFactory.decode(response, self.request)
        self.assertSignature(creds)


    def test_failsWithDifferentMethod(self):
        """
        L{JerseyCredentialFactory.decode} returns an L{IUsernameHashedPassword}
        provider which rejects a correct password for the given user if the
        challenge response request is made using a different HTTP method than
        was used to request the initial challenge.
        """
        c = self.credentialFactory.getChallenge(self.request)

        clientResponse = self.formatResponse(
            nonce=c['nonce'],
            response=self.getDigestResponse(challenge, nc),
            nc=nc,
            opaque=challenge['opaque'])
        creds = self.credentialFactory.decode(clientResponse, 'POST',
                                              self.clientAddress.host)
        self.assertFalse(creds.checkPassword(self.password))
        self.assertFalse(creds.checkPassword(self.password + 'wrong'))

    test_failsWithDifferentMethod.skip = "Method not in auth header."


    def test_noUsername(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} if the response
        has no username field or if the username field is empty.
        """
        c = self.credentialFactory.getChallenge(self.request)

        # Check for no username
        auth = self.buildAuth(nonce=c["nonce"], opaque=c["opaque"])
        del auth["username"]
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "'username' not in authorization.")

        # Check for an empty username
        auth["username"] = ""
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "Invalid username.")


    def test_noNonce(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} if the response
        has no nonce.
        """
        c = self.credentialFactory.getChallenge(self.request)

        # Check for no username
        auth = self.buildAuth(opaque=c["opaque"])
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "'nonce' not in authorization.")


    def test_noOpaque(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} if the response
        has no opaque.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(nonce=c["nonce"])
        rsp = self.formatResponse(**auth)
        e = self.assertRaises(LoginFailed,
            self.credentialFactory.decode, rsp, self.request)
        self.assertEqual(str(e), "'opaque' not in authorization.")


    def test_checkHash(self):
        """
        L{JerseyCredentialFactory.decode} returns an L{IUsernameDigestHash}
        provider which can verify a hash of the form 'username:realm:password'.
        """
        c = self.credentialFactory.getChallenge(self.request)
        auth = self.buildAuth(nonce=c["nonce"], opaque=c["opaque"])
        auth["signature"] = self.signAuth(auth, self.request)
        response = self.formatResponse(**auth)

        creds = self.credentialFactory.decode(response, self.request)

        try:
            verifyObject(IPrivateKey, creds)
        except:
            self.fail("{0.__class__.__name__} is not a private key".format(creds))

        safeData = str("{0[username]};{1};{0[realm]};"
                       "{0[nonce]};{0[opaque]};{0[blob]}"
                       ).format(auth, creds.client)
        digest = sha512(safeData).hexdigest()
        log.msg("Verifying data: {0} ({1}) ".format(safeData, digest))

        # Verify this signature with antelope's key.. It should pass.
        self.assertSignature(creds)

        # Try to verify this signature with monkey's key.. It should fail.
        badKey = self.keys["monkey"].pub
        self.assertNotEquals(badKey.blob(), creds.blob)
        self.assertFalse(badKey.verify(creds.signature, creds.data))


    def test_invalidOpaque(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} when the opaque
        value does not contain all the required parts.
        """
        credentialFactory = FakeJerseyCredentialFactory(self.realm)
        c = self.credentialFactory.getChallenge(self.request)

        client = self.request.getClientIP() or "0.0.0.0"
        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, 'badOpaque', c['nonce'],
            self.request)
        self.assertEqual(str(exc), "Invalid opaque value.")

        badOpaque = 'foo-' + 'nonce;clientip'.encode("base64").replace("\n","")

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, badOpaque, c['nonce'],
            self.request)
        self.assertEqual(str(exc), 'Invalid opaque value.')

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, '', c['nonce'], self.request)
        self.assertEqual(str(exc), 'Invalid opaque value.')

        badOpaque = 'foo-' + "{0};{1}".format(c['nonce'], client
                    ).encode("base64").replace("\n", "")
        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, badOpaque, c['nonce'],
            self.request)
        self.assertEqual(str(exc), 'Invalid opaque value.')


    def test_incompatibleNonce(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} when the given
        nonce from the response does not match the nonce encoded in the opaque.
        """
        credentialFactory = FakeJerseyCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)

        badOpaque = credentialFactory._buildOpaque('1234567890', self.request)

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, badOpaque, c['nonce'], self.request)
        self.assertEqual(str(exc), "Invalid opaque value.")

        exc = self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, badOpaque, "", self.request)
        self.assertEqual(str(exc), "Invalid opaque value.")


    def test_incompatibleClientIP(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} when the
        request comes from a client IP other than what is encoded in the
        opaque.
        """
        credentialFactory = FakeJerseyCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)

        badAddress = IPv4Address("TCP", "10.0.0.1", 43210)
        # Sanity check
        self.assertNotEqual(self.request.getClientIP(), badAddress.host)

        badRequest = self.makeRequest("GET", badAddress)
        badOpaque = credentialFactory._buildOpaque(c['nonce'], badRequest)

        self.assertRaises(
            LoginFailed,
            credentialFactory._verifyOpaque, badOpaque, c['nonce'], self.request)


    def test_oldNonce(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} when the given
        opaque is older than C{JerseyCredentialFactory.CHALLENGE_LIFETIME_SECS}
        """
        credentialFactory = FakeJerseyCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)

        client = self.clientAddress.host
        key = "%s;%s;%s" % (c['nonce'], client, '-137876876')
        digest = sha512(key + credentialFactory._secret).hexdigest()
        ekey = key.encode("base64").replace("\n", "")
        oldOpaque = '%s-%s' % (digest, ekey)

        self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, oldOpaque, c['nonce'],
            self.request)


    def test_mismatchedOpaqueChecksum(self):
        """
        L{JerseyCredentialFactory.decode} raises L{LoginFailed} when the opaque
        checksum fails verification.
        """
        credentialFactory = FakeJerseyCredentialFactory(self.realm)
        c = credentialFactory.getChallenge(self.request)
        client = self.clientAddress.host

        key = '%s;%s;%s' % (c['nonce'], client, '0')
        digest = sha512(key + 'this is not the right pkey').hexdigest()
        eKey = key.encode("base64").replace("\n", "")
        badChecksum = '%s-%s' % (digest, eKey)

        self.assertRaises(LoginFailed,
            credentialFactory._verifyOpaque, badChecksum, c['nonce'],
            self.request)


    def buildAuth(self, **kw):
        if 'username' not in kw:
            kw['username'] = self.username
        if 'realm' not in kw:
            kw['realm'] = self.realm
        if 'method' not in kw:
            kw['method'] = "publickey"

        privKey = kw.get("privKey", self.keys["antelope"].priv)
        if 'blob' not in kw:
            kw['blob'] = privKey.blob().encode("base64").replace("\n", "")

        return kw


    def signAuth(self, auth, request):
        """
        Calculate the response for the given challenge
        """
        client = request.getClientIP() or "0.0.0.0"
        blob = auth["blob"].decode("base64")
        data = str("{0[username]};{1};{0[realm]};"
                   "{0[nonce]};{0[opaque]};{2}"
                   ).format(auth, client, blob)

        kp = self.keys[auth["username"]]
        signature = kp.priv.sign(data)
        self.assertTrue(kp.pub.verify(signature, data))

        safeData = str("{0[username]};{1};{0[realm]};"
                       "{0[nonce]};{0[opaque]};{0[blob]}"
                       ).format(auth, client)
        digest = sha512(safeData).hexdigest()
        log.msg("Signed data: {0} ({1}) ".format(safeData, digest))

        return signature.encode("base64").replace("\n", "")


    def assertSignature(self, creds):
        key = self.keys[creds.username].pub
        self.assertEquals(key.blob(), creds.blob)
        self.assertTrue(key.verify(creds.signature, creds.data))


    def formatResponse(self, quotes=True, **kw):
        quote = '"' if quotes is True else ''
        return ', '.join([
                "{0}={2}{1}{2}".format(k, v, quote)
                for (k, v) in kw.iteritems()
                if v is not None])


