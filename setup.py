import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="wconv",
    version="0.8.0",
    author="Tobias Neitzel (@qtc_de)",
    author_email="",
    description="wconv - Converting Windows native formats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=[
                        'termcolor',
                     ],
    packages=setuptools.find_packages(),
    scripts=[
            'bin/wconv',
            ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
    ],
)
