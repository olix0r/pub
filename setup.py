#!/usr/bin/env python2.6

try:
    from setuptools import setup
except:
    from distutils.core import setup


def getVersion():
    import os
    packageSeedFile = os.path.join("lib", "_version.py")
    ns = {"__name__": __name__, }
    execfile(packageSeedFile, ns)
    return ns["version"]

version = getVersion()


setup(
    name = version.package,
    version = version.short(),

    description = "Pub Client and Service",
    long_description = "Pub key management service and client",

    author = "Oliver Gould", author_email = "ver@yahoo-inc.com",
    maintainer = "Oliver Gould", maintainer_email = "ver@yahoo-inc.com",

    packages = ["pub", "pub.cases", "pub.client", "twisted.plugins", ],
    scripts = ["bin/jget", "bin/pubc", ],
    package_dir = {"pub": "lib", },
    package_data = {"twisted.plugins": ["pubs.py"], },

    requires = [
        "jersey(>=0.1.2)", "pendrell(>=0.3.1)",
        "Twisted", "pycrypto", "pyasn1",
        ],
    )


