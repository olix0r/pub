import os

from twisted.application.service import IService, MultiService
from twisted.internet import reactor
from twisted.internet.defer import (Deferred, inlineCallbacks, returnValue,
        succeed)
from twisted.python.filepath import FilePath
from zope.interface import Attribute, Interface, implements

from jersey import log
from jersey.cred.crypto import Key



class ICredEntityService(Interface):

    version = Attribute("Service version")


    def getEntity(id):
        pass

    def createEntity(id, name, primaryKey):
        pass

    def deleteEntity(id):
        pass

    def listEntities(offset=None, count=None):
        pass

    def searchEntities(id=None, name=None, keyId=None):
        pass

    def getKey(id):
        pass



class IEntity(Interface):

    id = Attribute("Identifier")
    type = Attribute("Entity type")
    primaryKey = Attribute("Entity's priamry Key")

    def getKey(id=None):
        """Get a Key belonging to the entity"""

    def addKey(id, type, key):
        pass

    def deleteKey(id):
        """Delete an entity's key"""

    def listKeys():
        """List all of the entity's keys."""


class IPublicKey(Interface):

    id = Attribute("Key ID")
    entity = Attribute("Key's entity.")
    type = Attribute("Key type (e.g. 'ssh-rsa')")

    def encrypt(data):
        """Encrypt data to this key"""

    def verify(signature, data):
        """Verify a signature made by an associated private key"""


class IRealm(Interface):

    name = Attribute("Realm name")

    def authorizeKey(key):
        """Authorize a key"""



class IPublicKeyService(Interface):

    def getPublicKeys(username, type=None):
        """Get public keys for a user.

        If 'type' is specified and not None, only keys of that type will be
        returned.
        """


class DirectoryBackedKeyService(MultiService):
    implements(IPublicKeyService)

    pubSuffix = "pub"


    def __init__(self, keyDir):
        MultiService.__init__(self)
        if not isinstance(keyDir, FilePath) :
            keyDir = FilePath(keyDir)
        assert keyDir.isdir()
        self.keyDir = keyDir


    def getPublicKeys(self, user, type=None):
        log.debug("Getting public keys for {0}".format(user))
        keys = list()
        for line in self._userKeyFileIterator(user):
            try:
                key = self._buildKey(line)
            except Exception, e:
                log.warn(e)
            else:
                if type is None or type == key.type():
                    log.debug("Loaded key: {0}".format(line))
                    keys.append(key)
        return succeed(keys)


    def _userKeyFileIterator(self, user):
        with self._openUserPubFile(user) as f:
            for line in f:
                line = line.strip()
                if not self._isCommentary(line):
                    yield line


    def _openUserPubFile(self, user):
        path = user
        if self.pubSuffix:
            path = os.path.extsep.join([path, self.pubSuffix])
        try:
            return self.keyDir.child(path).open()
        except IOError:
            raise NoSuchUser(user)


    @staticmethod
    def _isCommentary(line):
        return line.startswith("#")

    @staticmethod
    def _buildKey(line):
        return Key.fromString(line)



class NoSuchUser(KeyError):

    def __init__(self, user, *args, **kw):
        KeyError.__init__(self, user, *args, **kw)
        self.user = user


