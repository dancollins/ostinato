#!/usr/bin/env python
# Copyright (C) 2014 Srivats P.
# 
# This file is part of "Ostinato"
# 
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import json
import os
import shutil
import sys
from setuptools import Command, setup
from setuptools.command.sdist import sdist as _sdist

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def ensure_cwd():
    if os.path.split(os.getcwd())[1] != 'binding':
        print('ERROR: This script needs to be run from the binding directory')
        print('Current Working Directory is %s' % os.getcwd())
        sys.exit(1)

class sdist(_sdist):
    def run(self):
        ensure_cwd()
        _sdist.run(self)

class sdist_clean(Command):
    description = 'clean stuff generated by sdist'
    user_options = []
    def initialize_options(self):
        return

    def finalize_options(self):
        return

    def run(self):
        ensure_cwd()
        shutil.rmtree('dist', ignore_errors = True)
        shutil.rmtree('python-ostinato.egg-info', ignore_errors = True)
        shutil.rmtree('python_ostinato.egg-info', ignore_errors = True)

# ------- script starts from here ------- #

with open(os.path.join(os.path.dirname(__file__), 'pkg_info.json')) as f:
    pkg_info = json.load(f)

setup(name = 'python-ostinato',
      version = pkg_info['version'],
      author = 'Srivats P',
      author_email = 'pstavirs@gmail.com',
      license = "GPLv3+",
      url = 'http://ostinato.org',
      description = 'python-ostinato provides python bindings for the Ostinato network packet/traffic generator and analyzer',
      long_description = read('README.txt'),
      install_requires = ['protobuf>=2.3.0'],
      packages = ['ostinato', 'ostinato.protocols'],
      package_dir = {'ostinato': '.'},
      package_data = {'ostinato': ['pkg_info.json', 'LICENSE.txt']},
      platforms = ['Any'],
      classifiers = [
          'Development Status :: 4 - Beta',
          'Programming Language :: Python :: 2.7',
          'Intended Audience :: Telecommunications Industry',
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
          'Topic :: Software Development :: Testing :: Traffic Generation',
          'Topic :: System :: Networking'],
      cmdclass={
          'sdist': sdist,
          'sdist_clean': sdist_clean},
      )

