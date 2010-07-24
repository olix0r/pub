import os, sys

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.filepath import FilePath
from twisted.python.usage import UsageError

from zope.interface import implements

from jersey import log

from pub.client import cli
from pub.crypto import Key
from pub.iface import KeyAlreadyExists



class Options(cli.Options):

    optParameters = [
        ["comment", "c", "", "Key comment.",],
        ]

    def getSynopsis(self):
        return "{0} {1} [options] entity-id key-file".format(
                self.parent.getSynopsis(),
                self.parent.subCommand)


    def parseArgs(self, id, keyFile):
        self["id"] = id
        try:
            self["key"] = Key.fromFile(keyFile)
        except:
            raise UsageError("Invalid key file: {0}".format(keyFile))



class Command(cli.Command):

    _keyFmt = "\n".join([
            "Entity ID: {0.entityId}",
            "Key ID:    {0.id}",
            "Key Type:  {0.type}",
            "Comment:   {0.comment}",
            ])


    @inlineCallbacks
    def execute(self):
        log.debug("Registering an entity")
        try:
            ent = yield self.pub.getEntity(self.config["id"])
            pubKey = yield ent.registerKey(
                    self.config["key"], self.config["comment"])

        except KeyAlreadyExists:
            print >>sys.stderr, "Key already exists: {0}".format(
                    self.config["key"].id)

        else:
            log.debug("Registered a key")
            print self._keyFmt.format(pubKey)



class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "register-key"
    shortcut = "R"
    description = "Register an entity"


loader = Loader()

