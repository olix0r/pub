from twisted.trial.unittest import TestCase
from twisted.web.iweb import ICredentialFactory
from twisted.web.test.test_httpauth import RequestMixin

from zope.interface.verify import verifyObject

from jersey.auth.cred import JerseyCredentialFactory



class DigestAuthTestCase(RequestMixin, TestCase):
    """
    Digest authentication tests which use L{twisted.web.http.Request}.
    """

    def setUp(self):
        """
        Create a DigestCredentialFactory for testing
        """
        self.realm = "jungle test"
        self.credentialFactory = JerseyCredentialFactory(self.realm)
        self.request = self.makeRequest()


    def test_decode(self):
        """
        L{digest.DigestCredentialFactory.decode} calls the C{decode} method on
        L{twisted.cred.digest.DigestCredentialFactory} with the HTTP method and
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
        L{DigestCredentialFactory} implements L{ICredentialFactory}.
        """
        self.assertTrue(
            verifyObject(ICredentialFactory, self.credentialFactory))


    def test_getChallenge(self):
        """
        The challenge issued by L{DigestCredentialFactory.getChallenge} must
        include C{'qop'}, C{'realm'}, C{'algorithm'}, C{'nonce'}, and
        C{'opaque'} keys.  The values for the C{'realm'} and C{'algorithm'}
        keys must match the values supplied to the factory's initializer.
        None of the values may have newlines in them.
        """
        self._assertChallengeOK(self.request)


    def test_getChallengeWithoutClientIP(self):
        """
        L{DigestCredentialFactory.getChallenge} can issue a challenge even if
        the L{Request} it is passed returns C{None} from C{getClientIP}.
        """
        request = self.makeRequest("GET", None)
        self._assertChallengeOK(request)


    def _assertChallengeOK(self, request):
        challenge = self.credentialFactory.getChallenge(request)

        self.assertEquals(challenge["allowed-methods"], "publickey")
        self.assertEquals(challenge["realm"], "jungle test")
        self.assertIn("nonce", challenge)
        self.assertIn("opaque", challenge)
        for v in challenge.values():
            self.assertNotIn("\n", v)

        return challenge

