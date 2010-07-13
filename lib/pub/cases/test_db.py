
from twisted.internet.defer import (Deferred, inlineCallbacks, returnValue,
        maybeDeferred, succeed)
from twisted.trial.unittest import TestCase

from jersey.cred.crypto import Key
from jersey.cred.pub import db, iface



class _JournalingMockDB(object):

    def __init__(self):
        self.journal = []
        self.results = []

    def setResults(self, results):
        self.results = results

    class _Transaction(object):
        def __init__(self):
            self.journal = []
        def execute(self, sql, *args):
            self.journal.append(("EXECUTE", sql,) + args)

    @inlineCallbacks
    def runInteraction(self, interaction, *args, **kw):
        tx = self._Transaction()
        ret = yield maybeDeferred(interaction, tx, *args, **kw)
        self.journal.append(("TRANSACTION", tx.journal))
        returnValue(ret)


    def runOperation(self, sql, *args):
        self.journal.append(("EXECUTE", sql,) + args)
        return succeed(None)


    def runQuery(self, sql, *args):
        self.journal.append(("QUERY", sql,) + args)
        return succeed(self.results.pop(0) if self.results else [])



class PubServiceTest(TestCase):

    b64Key = ("AAAAB3NzaC1yc2EAAAADAQABAAABAQDOA8hcPwK+JLmANi2ZMdkLHfLWy9z"
            "ECfbaa9gkwfWR6mxvhs5R8CquDbjKBbp/f3g+WQ4TyOesV++QMxCYPuoevm86"
            "NyMJR9b6CFMaGynb4OhBIik5Dv8VH0ncifnGkZJxydlwrY3w8v6OqF9vWCn58"
            "vK0hWXjtdMYv+YWjie6hI14ZCJA6oivp5KWuzcIdYhk08rAcVS05aAaHTBuM8"
            "sX3nBxQA5CcYNcALKZGhcxiBteiCdEton066UTcT+KzbRr/evCukYnqwN9/jL"
            "JHFgzH7KIVHFDsH6Lc7NCrP1EkdTmKEgdr/OaOxAyAzyY+6YAdXqJNwUJ1uk5"
            "jRfz+Xwf")
    rawKey = b64Key.decode("base64")
    ent = ("0b0t", "MONKEYBOT", Key.fromString(rawKey))

    def setUp(self):
        self.db = _JournalingMockDB()
        self.svc = db.PubService(self.db)


    @inlineCallbacks
    def test_startService(self):
        self.svc.startService()
        yield self.svc._initialized
        self.assertEquals([
                ("EXECUTE", db.PubService._enableForeignKeySQL),
                ],self.db.journal)


    @inlineCallbacks
    def test_registerEntity(self):
        id, species, key = self.ent
        ent = yield self.svc.registerEntity(id, species, key)
        self.assertEquals([
                ("TRANSACTION", [
                    ("EXECUTE", db.PubService._registerEntitySQL,
                        (id, species, key.id)),
                    ("EXECUTE", db.Entity._registerKeySQL,
                        (key.id, key.type(), self.b64Key, "primary key", id)),
                ])], self.db.journal)
        self.assertIsInstance(ent, db.Entity)
        self.assertEquals(ent.id, id)
        self.assertEquals(ent.species, species)
        self.assertEquals(ent.primaryKeyId, key.id)


    @inlineCallbacks
    def test_getEntity(self):
        id, species, key = self.ent
        self.db.setResults([
            [(species, key.id), ],
            ])
        ent = yield self.svc.getEntity(id)
        self.assertIsInstance(ent, db.Entity)
        self.assertEquals(ent.id, id)
        self.assertEquals(ent.species, species)
        self.assertEquals(ent.primaryKeyId, key.id)
        self.assertEquals([
                ("QUERY", db.PubService._getEntitySQL, (id,)),
                ], self.db.journal)


    @inlineCallbacks
    def test_getEntity_NotFound(self):
        id = "0b0t"
        enf = yield self.assertFailure(self.svc.getEntity(id),
                iface.EntityNotFound)
        self.assertEquals(enf.entityId, id)
        self.assertEquals([
                ("QUERY", db.PubService._getEntitySQL, (id,)),
                ], self.db.journal)


    @inlineCallbacks
    def test_listSpecies(self):
        self.db.setResults([
            [("MONKEYBOT",), ("NANABOT",), ],
            ])
        species = yield self.svc.listSpecies()
        self.assertEquals(["MONKEYBOT", "NANABOT"], species)
        self.assertEquals([
                ("QUERY", db.PubService._listSpeciesSQL),
                ], self.db.journal)



class EntityTest(TestCase):

    entId = "0b0t"
    entSpecies = "MONKEYBOT"

    b64Key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDOA8hcPwK+JLmANi2ZMdkLHfLWy9zECfbaa9gkwfWR6mxvhs5R8CquDbjKBbp/f3g+WQ4TyOesV++QMxCYPuoevm86NyMJR9b6CFMaGynb4OhBIik5Dv8VH0ncifnGkZJxydlwrY3w8v6OqF9vWCn58vK0hWXjtdMYv+YWjie6hI14ZCJA6oivp5KWuzcIdYhk08rAcVS05aAaHTBuM8sX3nBxQA5CcYNcALKZGhcxiBteiCdEton066UTcT+KzbRr/evCukYnqwN9/jLJHFgzH7KIVHFDsH6Lc7NCrP1EkdTmKEgdr/OaOxAyAzyY+6YAdXqJNwUJ1uk5jRfz+Xwf"
    rawKey = b64Key.decode("base64")
    entKey = Key.fromString(rawKey)

    otherB64Key = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQFs425i4QBI5AlypIIueCFIdiosijL1f0fezNcbPW2JCbbdwVU9TXAadfOLxRoY6Nuliy98ji3Nd8NtjD/Cu9+PfTTHGKoCRakYKdxkUzvI6FXlwgRn2lcWPIg+1lXoO/K9yxcoT43whtZ1CLj24MPU2B75zBUkwmhnaXDNaElxzQ=="
    otherRawKey = otherB64Key.decode("base64")
    otherEntKey = Key.fromString(otherRawKey)


    def setUp(self):
        self.db = _JournalingMockDB()
        self.entity = db.Entity(self.entId, self.entSpecies, self.entKey.id,
                self.db)


    @inlineCallbacks
    def test_getKey_primary(self):
        comment = "primary key"
        self.db.setResults([
            [(self.b64Key, comment), ]
            ])
        key = yield self.entity.getKey()
        self.assertIsInstance(key, db.PublicKey)
        self.assertEquals(key.data, self.b64Key)
        self.assertEquals(key.id, self.entKey.id)
        self.assertEquals(key.comment, comment)
        self.assertEquals([
                ("QUERY", db.Entity._getKeySQL, (self.entKey.id, self.entId)),
                ], self.db.journal)


    @inlineCallbacks
    def test_getKey_primary(self):
        self.db.setResults([
            [(self.b64Key, "primary key"), ]
            ])
        key = yield self.entity.getKey()
        self.assertIsInstance(key, db.PublicKey)
        self.assertEquals(key.data, self.b64Key)
        self.assertEquals(key.id, self.entKey.id)
        self.assertEquals([
                ("QUERY", db.Entity._getKeySQL, (self.entKey.id, self.entId)),
                ], self.db.journal)


    @inlineCallbacks
    def test_registerKey(self):
        comment = "other key"
        self.db.setResults([
            [(self.otherB64Key, comment), ]
            ])
        key = yield self.entity.getKey(self.otherEntKey.id)
        self.assertIsInstance(key, db.PublicKey)
        self.assertEquals(key.data, self.otherB64Key)
        self.assertEquals(key.id, self.otherEntKey.id)
        self.assertEquals([
                ("QUERY", db.Entity._getKeySQL, (
                    self.otherEntKey.id, self.entId
                )), ], self.db.journal)


