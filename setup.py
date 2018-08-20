from setuptools import setup, find_packages

setup(
    name='oidc_lib',
    version='1.0.0',
    description='A simple library to connect with OpenID',
    url='https://gitlab.atm.dknotus.pl:8888/notus/oidclib',
    author='Notus Finanse S.A',
    author_email='it.rozwoj@notusfinanse.pl',
    classifiers=[
        'Development Status :: 3 -  Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.5.2',
    ],
    keywords='OpenID library',
    packages=find_packages(),
    install_requires=['flask', 'pyjwkest', 'pyyaml', 'requests'],
    python_requires='>=3.5.2',

)
