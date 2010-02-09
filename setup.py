#/usr/bin/env python2.6

from distutils.core import setup


description = """
Jersey Services:
    - Authentication
"""


def getVersion():
    import os
    packageSeedFile = os.path.join("jersey", "_version.py")
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

    packages = [
        "jersey",
        "jersey.cases",
        "jersey.auth",
        "twisted.plugins",
        ],
    py_modules = [
        "jersey.auth.cred",
        "jersey.auth.service", "jersey.cases.test_auth_service",
        "jersey.auth.ws",

        "jersey._version",
        ],
    package_data = {
        "jersey.cases": [
            "animals_keys/antelope",
            "animals_keys/monkey",
            ],
        "twisted.plugins": ["cred.jersey.ops.py",],
        },

    )


