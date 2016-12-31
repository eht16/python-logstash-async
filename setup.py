# -*- coding: utf-8 -*-

from os import path
from setuptools import setup
from shutil import rmtree
import sys

NAME = 'python-logstash-async'
VERSION = '1.1.0'

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst')) as f:
    LONG_DESCRIPTION = f.read().decode('utf-8')


if 'bdist_wheel' in sys.argv:
    # Remove previous build dir when creating a wheel build, since if files have been removed
    # from the project, they'll still be cached in the build dir and end up as part of the
    # build, which is really neat!
    for directory in ('build', 'dist', 'python_logstash_async.egg-info'):
        try:
            rmtree(directory)
        except:
            pass


setup(
    name=NAME,
    packages=['logstash_async'],
    version=VERSION,
    description='Asynchronous Python logging handler for Logstash.',
    long_description=LONG_DESCRIPTION,
    license='MIT',
    author='Enrico Tröger',
    author_email='enrico.troeger@uvena.de',
    url='https://github.com/eht16/python-logstash-async',
    keywords='logging logstash asynchronous',
    install_requires=['six'],
    setup_requires=['flake8'],
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Logging',
    ]
)
