
from twisted.internet.defer import (Deferred, inlineCallbacks, returnValue,
        maybeDeferred, succeed)
from twisted.trial.unittest import TestCase

from jersey.cred.crypto import Key
from jersey.cred.pub import db, iface



class _MockDBSensor(object):

    def __init__(self):
        self.journal = []


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
        return succeed([])



class PubServiceTest(TestCase):

    def setUp(self):
        self.db = _MockDBSensor()
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
        b64Key = ("AAAAB3NzaC1yc2EAAAADAQABAAABAQDOA8hcPwK+JLmANi2ZMdkLHfLWy9z"
                "ECfbaa9gkwfWR6mxvhs5R8CquDbjKBbp/f3g+WQ4TyOesV++QMxCYPuoevm86"
                "NyMJR9b6CFMaGynb4OhBIik5Dv8VH0ncifnGkZJxydlwrY3w8v6OqF9vWCn58"
                "vK0hWXjtdMYv+YWjie6hI14ZCJA6oivp5KWuzcIdYhk08rAcVS05aAaHTBuM8"
                "sX3nBxQA5CcYNcALKZGhcxiBteiCdEton066UTcT+KzbRr/evCukYnqwN9/jL"
                "JHFgzH7KIVHFDsH6Lc7NCrP1EkdTmKEgdr/OaOxAyAzyY+6YAdXqJNwUJ1uk5"
                "jRfz+Xwf")
        rawKey = b64Key.decode("base64")
        id, species, key = "0b0t", "MONKEYBOT", Key.fromString(rawKey)
        ent = yield self.svc.registerEntity(id, species, key)
        self.assertEquals([
                ("TRANSACTION", [
                    ("EXECUTE", db.PubService._registerEntitySQL,
                        (id, species, key.id)),
                    ("EXECUTE", db.Entity._registerKeySQL,
                        (key.id, key.type(), b64Key, "primary key", id)),
                ])], self.db.journal)
        self.assertIsInstance(ent, db.Entity)


    @inlineCallbacks
    def test_getEntity_NotFound(self):
        id = "0b0t"
        enf = yield self.assertFailure(self.svc.getEntity(id), iface.EntityNotFound)
        self.assertEquals(enf.entityId, id)
        self.assertEquals([
                ("QUERY", db.PubService._getEntitySQL, (id,)),
                ], self.db.journal)



