
from twisted.application.service import IService, MultiService
from twisted.conch.ssh.keys import Key
from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.python.filepath import FilePath
from twisted.python import log

from zope.interface import Interface, implements



class IPublicKeyService(Interface):

    def getPublicKeys(username, type=None):
        """Get public keys for a user.

        If 'type' is specified and not None, only keys of that type will be
        returned.
        """


class DirectoryBackedKeyService(MultiService):
    implements(IPublicKeyService)

    def __init__(self, keyDir):
        self.keyDir = k = FilePath(keyDir)
        assert k.isdir()


    def _openUserFile(self, user):
        try:
            child = self.keyDir.child(user)
            return child.open()

        except IOError:
            raise NoSuchUser(user)


    @inlineCallbacks
    def getPublicKeys(self, user, type=None):
        def _control():
            d = Deferred()
            reactor.callLater(0, d.callback, True)
            return d

        keys = list()
        with self._openUserFile(user) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("#"):
                    try:
                        key = Key.fromString(line)
                        if type is None or type == key.type():
                            keys.append(key)

                    except Exception, e:
                        log.msg(e)

                yield _control()

        returnValue(keys)



class NoSuchUser(KeyError):

    def __init__(self, user, *args, **kw):
        KeyError.__init__(self, user, *args, **kw)
        self.user = user


