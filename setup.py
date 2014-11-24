import os

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

with open('LICENSE.txt') as f:
    license = f.read()

exec(open(os.path.join('SimpleAciUiLogServer', 'version.py')).read())

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
    download_url = DOWNLOADURL,
    license=license,
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