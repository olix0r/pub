#/usr/bin/env python2.6

from distutils.core import setup


description = """
Jersey Services:
    - Authentication
"""


def getVersion():
    import os
    packageSeedFile = os.path.join("lib", "_version.py")
    ns = {"__name__": __name__, }
    execfile(packageSeedFile, ns)
    return ns["version"]

version = getVersion()


setup(
    name = "jersey",
    version = version.short(),

    description = "Jersey Services",
    long_description = description,

    author = "Oliver Gould", author_email = "ver@yahoo-inc.com",
    maintainer = "Oliver Gould", maintainer_email = "ver@yahoo-inc.com",

    requires = ["jersey", "twisted", "twisted.conch", "twisted.web", ],
    packages = [
        "jersey.auth", "jersey.auth.cases",
        "twisted.plugins",
        ],
    package_dir = {
        "jersey.auth": "lib",
        "jersey.auth.cases": "lib/cases",
        },
    package_data = {
        "jersey.auth.cases": ["animals/{0}{1}".format(animal, ext) 
                                for animal in ("antelope", "monkey")
                                for ext in (".pub", "")
                                ],
        "twisted.plugins": ["cred.jersey.ops.py",],
        },

    )


