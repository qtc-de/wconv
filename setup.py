#!/usr/bin/python3

from os.path import expanduser, abspath, dirname, isdir, isfile
from shutil import copy

from setuptools import setup
from setuptools.command.install import install


name = 'wconv'
with open("README.md", "r") as fh:
    long_description = fh.read()


class PostInstall(install):
    '''
    Subclass to allow running commands after package installation. Required for setup of the
    completion script.
    '''
    def run(self):
        PostInstall.setup_completion()
        install.run(self)

    def setup_completion():
        '''
        Checks whether the '~/.bash_completion.d' folder exists and copies the autocompletion script
        into it. If the folder does not exist the function just returns. The completion script is
        expected to be sored in the path: {mdoule_path}/{name}/resources/bash_completion.d/{name}

        Parameters:
             None

         Returns:
             None
        '''
        user_home = expanduser("~")
        module_path = abspath(dirname(__file__))

        completion_dir = f'{user_home}/.bash_completion.d/'
        if not isdir(completion_dir):
            return

        completion_file = f'{module_path}/{name}/resources/bash_completion.d/{name}'
        completion_target = f'{completion_dir}/{name}'

        if not isfile(completion_file):
            return

        copy(completion_file, completion_target)


setup(
    url='https://github.com/qtc-de/wconv',
    name=name,
    author='Tobias Neitzel (@qtc_de)',
    version='1.0.1',
    author_email='',

    description='wconv - Converting Windows native formats to human readable form',
    long_description=long_description,
    long_description_content_type='text/markdown',

    packages=['wconv'],
    package_data={
                        name: [
                            'resources/*',
                            'resources/bash_completion.d/*',
                        ]
                   },
    install_requires=[
                        'termcolor',
                     ],
    scripts=[
                f'bin/{name}',
            ],
    cmdclass={
                'install': PostInstall,
             },
    classifiers=[
                    'Programming Language :: Python :: 3',
                    'Operating System :: Unix',
                    'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
                ],
)
