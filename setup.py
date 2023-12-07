from setuptools import setup, find_packages

DESC = 'A hashing and encryption with Customizable Hashing Algorithm CHA, WARNING: DO NOT USE IN REAL USE CASES! THIS WAS MADE JUST FOR FUN!'
with open("README.md", 'r') as f:
    LONG_DESC = f.read()
setup(
    name="cha_hashing",
    version="0.4.8.5.6.4",
    author="Roy Nisimov",
    description=DESC,
    long_description_content_type="text/markdown",
    long_description=LONG_DESC,
    packages=find_packages(),
    url='https://github.com/RoyNisimov1/CHA',
    license='MIT',
    install_requires=[],
    keywords=['python', 'hashin', 'cha', 'encryption', 'decryption'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
