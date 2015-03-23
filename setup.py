import os

from setuptools import setup, find_packages

with open('LICENSE.txt') as f:
    LICENSE = f.read()

__version__ = ""
version = open(os.path.join('SimpleAciUiLogServer', 'version.py')).read()
exec(version)  # pylint:disable=exec-used

PKGNAME = 'SimpleAciUiLogServer'
URL = 'https://github.com/datacenter/' + PKGNAME
DOWNLOADURL = URL + '/releases/tag/' + str(__version__)

setup(
    name=PKGNAME,
    version=__version__,
    description='A remote API Inspector written in Python',
    long_description=open('README.rst').read(),
    packages=find_packages(),
    url=URL,
    download_url=DOWNLOADURL,
    license=LICENSE,
    author='Mike Timm',
    author_email='mtimm@cisco.com',
    zip_safe=False,
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
    scripts=[os.path.join('SimpleAciUiLogServer', 'SimpleAciUiLogServer.py')],
    entry_points={
        "console_scripts": [
            "acilogserv=SimpleAciUiLogServer:main",
            "SimpleAciUiLogServer=SimpleAciUiLogServer:main"
        ],
    },
)
