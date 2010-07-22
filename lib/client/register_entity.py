import os, sys

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.filepath import FilePath
from twisted.python.usage import UsageError

from zope.interface import implements

from jersey import log

from pub.client import cli
from pub.crypto import Key
from pub.iface import EntityAlreadyExists



class Options(cli.Options):

    defaultSpecies = "HUMAN"

    optParameters = [
            ["species", "s", defaultSpecies, "Entity species",]
        ]


    def getSynopsis(self):
        return "{0} {1} [-s] id key-file".format(
                self.parent.getSynopsis(),
                self.parent.subCommand)


    def parseArgs(self, id, keyFile):
        self["id"] = id
        try:
            self["key"] = Key.fromFile(keyFile)
        except:
            raise UsageError("Invalid key file: {0}".format(keyFile))



class Command(cli.Command):

    _entFmt = "\n".join([
            "Identifier:  {0.id}",
            "Species:     {0.species}",
            "Primary key: {0.primaryKeyId}",
            ])


    @inlineCallbacks
    def execute(self):
        log.debug("Registering an entity")
        entId = self.config["id"]
        try:
            ent = yield self.pub.registerEntity(entId, self.config["species"],
                    self.config["key"])

        except EntityAlreadyExists:
            print >>sys.stderr, "Entity already exists: {0}".format(entId)

        else:
            log.debug("Registered an entity")
            print self._entFmt.format(ent)



class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "register-entity"
    shortcut = "r"
    description = "Register an entity"


loader = Loader()

