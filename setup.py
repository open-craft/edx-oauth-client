from setuptools import setup, find_packages


with open('requirements.txt', 'r') as f:
    requirements = f.readlines()


setup(
    name='edx-oauth-client',
    version='2.1.1',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/raccoongang/edx_oauth_client',
    install_requires=[
        "Django",
        "social-auth-core",
        "social-auth-app-django",
    ],
    packages=find_packages(exclude=['tests']),
)
