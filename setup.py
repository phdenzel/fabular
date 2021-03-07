from setuptools import setup
from setuptools import find_packages

with open(file="README.md", mode="r") as readme_f:
    long_description = readme_f.read()

setup(

    # Metadata
    name="fabular",
    author="Philipp Denzel",
    author_email="phdenzel@gmail.com",
    version="0.0.dev1",
    description=("A command-line chat app for secure communication "
                 "between you and your friends!"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='GNU General Public License v3.0',
    url="https://github.com/phdenzel/fabular",
    keywords="command line, chat, secure, encryption, server, client",
    classifiers=[
        'Development Status :: 1 - Alpha',
        'License :: GNU General Public License v3.0',
        'Operating System :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Chat server',
        'Topic :: Chat client',
        'Topic :: Secure communication',
    ],

    # Package
    install_requires=[],
    packages=find_packages(
        where='src',
        exclude=['tests*'],
    ),
    package_dir={"": "src"},
    py_modules=['fabular'],
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'fabular = fabular.__main__:main',
        ],
    },

)
