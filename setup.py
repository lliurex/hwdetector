#!/usr/bin/env python
from setuptools import setup

if __name__ == '__main__':
    setup(name='hwdetector',
    version='0.1',
    description='Simple system detector',
    author='Lliurex Team',
    author_email='m.angel.juan@gmail.com',
    maintainer='M.Angel Juan',
    maintainer_email='m.angel.juan@gmail.com',
    keywords=['detector'],
    url='http://lliurex.net',
    license='GPL',
    platforms='UNIX',
    package_dir={'':'hwdetector.install'},
    packages = ['hwdetector','hwdetector/modules','hwdetector/utils'],
    include_package_data = True,
    data_files = [],
    )