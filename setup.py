import os
from os.path import join, dirname, split
#from distutils.core import setup
from setuptools import setup, find_packages


with open('requirements.txt', 'r') as f:
    requirements = f.readlines()


setup(
    name='edx-oauth-client',
    version='ucdc-v.0.1.0',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/raccoongang/edx_oauth_client',
    
    install_requires=requirements,
    packages=find_packages(exclude=['tests']),
)
