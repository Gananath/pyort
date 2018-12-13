import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()
    
setup(
    # Needed to silence warnings (and to be a worthwhile package)
    name='pyort',
    url='https://github.com/Gananath/pyort',
    author='Gananath R',
    author_email='no-mail@no-mail.com',
    # Needed to actually package something
    packages=['pyort'],
    # Needed for dependencies
    install_requires=['psutil','argparse','configparser','ipaddress'],
    # *strongly* suggested for sharing
    version='0.1.7.5.91',
    # Long description
    #long_description=read('README.md'),
    entry_points = {
        'console_scripts': [
            'pyort=pyort.pyort:main',
        ],
    },
    # The license can be anything you like
    license='MIT',
    description='Command line tool for monitoring all network connections',
    # We will also need a readme eventually (there will be a warning)
    # long_description=open('README.txt').read(),
)
