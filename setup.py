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
    name = version.package,
    version = version.short(),

    description = "Jersey Auth Services",
    long_description = description,

    author = "Oliver Gould", author_email = "ver@yahoo-inc.com",
    maintainer = "Oliver Gould", maintainer_email = "ver@yahoo-inc.com",

    requires = ["jersey", "twisted", "twisted.conch", "pendrell(>=0.2.0)", ],
    packages = [
        "jersey.cred", "jersey.cred.cases",
        "twisted.plugins",
        ],
    scripts = ["bin/jget"],
    package_dir = {
        "jersey.cred": "lib",
        "jersey.cred.cases": "lib/cases",
        },
    package_data = {
        "jersey.cred.cases": ["animals/{0}{1}".format(animal, ext) 
                                for animal in ("antelope", "monkey")
                                for ext in (".pub", "")],
        "twisted.plugins": ["cred.jersey.ops.py"],
        },

    )


