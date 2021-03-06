"""
SQLite3-backed Pub Service
"""

from sqlite3 import IntegrityError

from twisted.application.service import MultiService
from twisted.internet.defer import (Deferred, inlineCallbacks, returnValue,
        maybeDeferred, succeed)
from zope.interface import implements

from jersey import log

from pub import version as VERSION
from pub.crypto import Key
from pub import iface



def connectDB(dbType, *args, **kw):
    from twisted.enterprise import adbapi
    kw.setdefault("check_same_thread", False)
    return adbapi.ConnectionPool(dbType, *args, **kw)



class PubService(MultiService):
    implements(iface.IPubService)

    version = VERSION.short()


    def __init__(self, db):
        MultiService.__init__(self)
        self._db = db
        self._initialized = None


    def startService(self):
        MultiService.startService(self)
        self._initialized = self._initializeDB()


    _enableForeignKeySQL = "PRAGMA foreign_keys=ON"

    def _initializeDB(self):
        return self._db.runOperation(self._enableForeignKeySQL)


    def _buildEntity(self, id, species, primaryKeyId):
        return Entity(id, species, primaryKeyId, self._db)


    _getEntitySQL = "SELECT species,primary_key_id FROM Entity WHERE id=?"

    @inlineCallbacks
    def getEntity(self, id):
        rows = yield self._db.runQuery(self._getEntitySQL, (id,))
        if not rows:
            raise iface.EntityNotFound(id)
        species, pkId = rows[0]
        ent = self._buildEntity(id, species, pkId)
        returnValue(ent)


    @inlineCallbacks
    def registerEntity(self, id, species, primaryKey, _tx=None):
        """
        Arguments:
            id --  Entity id
            species --  Entity species name.
            primaryKey --  Entity's primary public key.  Instance of
                pub.crypto.Key.
        """
        log.debug("Registering entity: {0}".format(id))
        ent = self._buildEntity(id, species, primaryKey.id)

        try:
            if _tx:
                yield self._db_registerEntity(_tx, ent, primaryKey)
            else:
                yield self._db.runInteraction(
                        self._db_registerEntity, ent, primaryKey)

        except IntegrityError, err:
            if err.args[0] == "column id is not unique":
                raise iface.EntityAlreadyExists(id)
            else:
                raise err

        else:
            log.debug("Registered entity: {0!r}".format(ent))
            returnValue(ent)


    _registerEntitySQL = "INSERT INTO Entity VALUES(?,?,?)"

    def _db_registerEntity(self, tx, ent, primaryKey):
        args = (ent.id, ent.species, ent.primaryKeyId)
        tx.execute(self._registerEntitySQL, args)
        ent.registerKey(primaryKey, "primary key", _tx=tx)
        log.debug("Registered key: {0!r}".format(primaryKey))


    def unregisterEntity(self, id, _tx=None):
        """
        Arguments:
            id --  Entity id
        """
        if _tx:
            return self._db_unregisterEntity(_tx, id)
        else:
            return self._db.runInteraction(self._db_unregisterEntity, id)


    _unregisterEntitySQL = "DELETE FROM Entity WHERE id=?"
    _unregisterEntityKeysSQL = "DELETE FROM Key WHERE entity_id=?"

    def _db_unregisterEntity(self, tx, id):
        args = (id, )
        tx.execute(self._unregisterEntitySQL, args)
        tx.execute(self._unregisterEntityKeysSQL, args)


    def search(self, id=None, species=None, keyId=None, comment=None,
            offset=None, count=None):
        raise NotImplemented()


    _listEntitiesSQL = "SELECT id FROM Entity"

    @inlineCallbacks
    def listEntities(self):
        """List all known species."""
        rows = yield self._db.runQuery(self._listEntitiesSQL)
        returnValue([name for (name,) in rows])


    _listSpeciesSQL = "SELECT name FROM Species"

    @inlineCallbacks
    def listSpecies(self):
        """List all known species."""
        rows = yield self._db.runQuery(self._listSpeciesSQL)
        returnValue([name for (name,) in rows])



class Entity(object):
    implements(iface.IEntity)

    def __init__(self, id, species, primaryKeyId, db):
        self._db = db
        self.id = id
        self.species = species
        self.primaryKeyId = primaryKeyId


    def _buildKey(self, key, comment):
        if isinstance(key, basestring):
            try:
                key = Key.fromString(key)
            except:
                raise ValueError("Invalid key data")
        if not isinstance(key, Key):
            raise ValueError("Invalid key")
        return PublicKey(key, self.id, comment, self._db)


    def getKey(self, id=None):
        """Get a Key belonging to the entity"""
        if id == None:
            id = self.primaryKeyId
        log.debug("Getting {0}'s key: {1}".format(self.id, id))
        return self._db_getKey(id)


    _getKeySQL = "SELECT data,comment FROM Key WHERE id=? AND entity_id=?"

    @inlineCallbacks
    def _db_getKey(self, id):
        rows = yield self._db.runQuery(self._getKeySQL, (id, self.id))
        if not rows:
            raise iface.KeyNotFound(id)
        data, comment = rows[0]
        data = data.decode("base64")
        k = self._buildKey(data, comment)
        returnValue(k)


    def registerKey(self, key, comment, _tx=None):
        log.debug("Registering key: {0.id}".format(key))
        pk = self._buildKey(key, comment)
        log.debug("Registering key: {0.id}".format(pk))

        if _tx:
            # Already in a transaction
            self._db_registerKey(_tx, pk)
            return succeed(pk)

        else:
            return self._db.runInteraction(self._db_registerKey, pk)


    _registerKeySQL = "INSERT INTO Key VALUES(?,?,?,?,?)"

    def _db_registerKey(self, tx, key):
        try:
            args = (key.id, key.type, key.data, key.comment, key.entityId)
            tx.execute(self._registerKeySQL, args)

        except IntegrityError, err:
            if err.args[0] == "column id is not unique":
                raise iface.KeyAlreadyExists(key)
            else:
                raise err

        else:
            return key


    _listKeysSQL = "SELECT id,type,comment FROM Key WHERE entity_id=?"

    @inlineCallbacks
    def listKeys(self):
        """Return a list of (id, type, comment) tuples."""
        rows = yield self._db.runQuery(self._listKeysSQL, (self.id,))
        keyInfos = {}
        for keyId, keyType, comment in rows:
            keyInfos[keyId] = (keyType, comment)
        returnValue(keyInfos)



class PublicKey(object):
    implements(iface.IPublicKey)

    def __init__(self, key, entityId, comment, db):
        """
        Arguments:
          key -- Instance of crypto.Key.
          entityId -- Key owner id.
        """
        self._db = db
        self._key = key.public()  # Icky private stuff go away!
        self.entityId = entityId
        self.comment = comment


    @property
    def id(self):
        return self._key.id

    @property
    def data(self):
        return self._key.blob().encode("base64").replace("\n", "")

    @property
    def type(self):
        return self._key.type()


    def encrypt(self, data):
        return self._key.encrypt(data)

    def verify(self, sig, data):
        return self._key.verify(sig, data)



