from setuptools import setup, find_packages


with open('requirements.txt', 'r') as f:
    requirements = f.readlines()


setup(
    name='edx-oauth-client',
    version='2.0',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/raccoongang/edx_oauth_client',
    install_requires=[
        "Django>=2.2,<2.3",
        "requests",
        "social-auth-core>=1.7,<2.0",
        "social-auth-app-django>=2.1,<3.0",
    ],
    packages=find_packages(exclude=['tests']),
)
