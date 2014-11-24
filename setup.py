import os

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

with open('LICENSE') as f:
    license = f.read()

exec(open(os.path.join('SimpleAciUiLogServer', 'version.py')).read())

setup(
    name='SimpleAciUiLogServer',
    version=__version__,
    description='A remote API Inspector written in Python',
    long_description=open('README.md').read(),
    packages=find_packages(),
    url='http://www.cisco.com/go/aci',
    license='Apache 2.0',
    author='Mike Timm',
    author_email='mtimm@cisco.com',
    zip_safe=False,
    classifiers=(
        'Development Status :: 3 - Beta',
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