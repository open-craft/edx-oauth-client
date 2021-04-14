from setuptools import setup, find_packages


with open('requirements.txt', 'r') as f:
    requirements = f.readlines()


setup(
    name='edx-oauth-client',
    version='1.0.2',
    description='Client OAuth2 from edX installations',
    author='edX',
    url='https://github.com/raccoongang/edx_oauth_client',

    install_requires=requirements,
    packages=find_packages(exclude=['tests']),
    package_dir={
        'edx_oauth_client': 'edx_oauth_client',
    },
    package_data={
        "edx_oauth_client": [
            'templates/*',
        ],
    },
)
