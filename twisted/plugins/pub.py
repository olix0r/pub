from os import geteuid
from time import time

from twisted.application.service import IServiceMaker, MultiService
from twisted.application.internet import TCPServer
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.portal import IRealm, Portal
from twisted.plugin import IPlugin
from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.python.filepath import FilePath
from twisted.python.usage import Options, UsageError

from twisted.web.resource import IResource, Resource
from twisted.web.server import Site

from zope.interface import implements

from jersey.cred.pub import db as pubdb, iface



class PubOptions(Options):

    _WWW_PORT = 80 if geteuid() == 0 else 8080
    _MIN_PORT = 1
    _MAX_PORT = 2 ** 16 - 1

    @classmethod
    def _toPort(Class, port):
        try:
            port = int(port)
        except ValueError:
            raise UsageError("invalid port: {0}".format(port))
        else:
            if not (Class._MIN_PORT <= port <= Class._MAX_PORT):
                raise UsageError("Invalid port number: {0}".format(port))
        return port


    optParameters = [
        ["www-port", "p", _WWW_PORT, "Web Service Port", _toPort],
        ]


    synopsis = "[options] db-path"

    def parseArgs(self, dbPath):
        self["db"] = dbPath



class ServiceMaker(object):
    implements(IServiceMaker, IPlugin)

    tapname = "pub"
    description = "Pub Key Service"
    options = PubOptions


    def makeService(self, opts):
        db = self.connectDB(opts)
        svc = pubdb.PubService(db)
        self.connectWWW(svc, opts)
        return svc


    def connectDB(self, svc, opts):
        return pubdb.connectDB("sqlite3", opts["db-path"])

    def connectWWW(self, svc, opts):
        site = self.buildSite(svc)
        www = TCPServer(opts["www-port"], site)
        www.setServiceParent(svc)
        return www


    def buildSite(self, svc):
        root = IResource(svc)
        return Site(root)


PubMaker = ServiceMaker()

