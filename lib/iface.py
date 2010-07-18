"""
A set of promises.  From me to you.
"""

from twisted.application.service import IService
from zope.interface import Attribute, Interface


class IPubService(Interface):

    version = Attribute("Service version")

    def getEntity(id):
        pass

    def registerEntity(id, species, primaryKey):
        pass

    #def deleteEntity(id):
    #    pass

    def listEntities():
        pass

    def search(id=None, species=None, keyId=None, comment=None):
        """Search Entities (and by extension, their keys)
        """

    def listSpecies():
        """List all known species."""



class IEntity(Interface):

    id = Attribute("Identifier")
    species = Attribute("Entity species")
    primaryKeyId = Attribute("Entity's primary Key ID")

    def getKey(id=None):
        """Get a Key belonging to the entity"""

    def registerKey(key, comment):
        pass

    #def deleteKey(id):
    #    """Delete an entity's key"""

    def listKeys():
        """List all of the entity's keys."""



class IPublicKey(Interface):

    id = Attribute("Key ID")
    entityId = Attribute("Key owner's identifier")
    type = Attribute("Key type (e.g. 'RSA')")

    def encrypt(data):
        """Encrypt data to this key"""

    def verify(signature, data):
        """Verify a signature made by an associated private key"""


class IRealm(Interface):

    range = Attribute("I.e. 'range' in 'range@domain.tld'")
    domain = Attribute("I.e. 'domain' in 'range@domain.tld'")

    def authorizeKey(key):
        """Authorize a key"""



class EntityAlreadyExists(KeyError):

    def __init__(self, entityId, *args, **kw):
        KeyError.__init__(self, entityId, *args, **kw)
        self.entityId = entityId


class EntityNotFound(KeyError):

    def __init__(self, entityId, *args, **kw):
        KeyError.__init__(self, entityId, *args, **kw)
        self.entityId = entityId


class KeyAlreadyExists(KeyError):

    def __init__(self, key, *args, **kw):
        KeyError.__init__(self, key.id, *args, **kw)
        self.key = key


class KeyNotFound(KeyError):

    def __init__(self, keyId, *args, **kw):
        KeyError.__init__(self, keyId, *args, **kw)
        self.keyId = keyId


class PrimaryKeyDeletionError(Exception):
    pass


class KeyAlreadyExists(Exception):
    pass



