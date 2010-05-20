import os

from twisted.internet.defer import inlineCallbacks
from twisted.trial import util
from twisted.trial.unittest import TestCase
from twisted.python.filepath import FilePath



class AnimalKeysTestBase(object):

    antelopeKey = {
        "type": "RSA",
        "fingerprint": "ed:3d:8d:1e:4a:eb:14:a0:36:0b:21:f4:84:ff:14:54"
        }
    monkeyKey = {
        "type": "DSA",
        "fingerprint": "e6:00:a9:ac:1f:a7:ee:fe:07:b7:44:c5:e4:d2:54:ed"
        }


    # XXX The amk Crypto lib is not yet python2.6-sane...
    suppress = [
        util.suppress(module="Crypto.Hash", category=DeprecationWarning),
        ]


    def setUp(self):
        testDir, testFile = os.path.split(__file__)
        self.keyDir = kd = FilePath(os.path.join(testDir, "animals"))
        self.assertTrue(kd.isdir(), "No pub key dir: {0.path}".format(kd))


    def assertKey(self, expected, key):
        self.assertEquals(expected["type"], key.type())
        self.assertEquals(expected["fingerprint"], key.fingerprint())



class DirectoryKeyServiceTestCase(AnimalKeysTestBase, TestCase):


    def setUp(self):
        AnimalKeysTestBase.setUp(self)
        from jersey.auth.service import DirectoryBackedKeyService
        self.svc = DirectoryBackedKeyService(self.keyDir.path)


    @inlineCallbacks
    def test_antelope_rsa(self):
        keys = yield self.svc.getPublicKeys("antelope")
        self.assertEquals(1, len(keys))
        self.assertKey(self.antelopeKey, keys[0])


    @inlineCallbacks
    def test_monkey_dsa(self):
        keys = yield self.svc.getPublicKeys("monkey")
        self.assertEquals(1, len(keys))
        self.assertKey(self.monkeyKey, keys[0])


    def test_yeti_NoSuchUser(self):
        """Fool, the Yeti doesn't exist."""
        from jersey.auth.service import NoSuchUser

        def _eb(nsu):
            self.assertEquals("yeti", getattr(nsu, "user", None))

        return self.assertFailure(self.svc.getPublicKeys("yeti"), NoSuchUser
                ).addErrback(_eb)


