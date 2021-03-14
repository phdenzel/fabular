import os
from setuptools import setup
from setuptools import find_packages

ld = {}
if os.path.exists("README.md"):
    ld['filename'] = "README.md"
    ld['content_type'] = "text/markdown"
elif os.path.exists("readme_src.org"):
    ld['filename'] = "readme_src.org"
    ld['content_type'] = "text/plain"

with open(file=ld['filename'], mode="r") as readme_f:
    ld['data'] = readme_f.read()

setup(

    # Metadata
    name="fabular",
    author="Philipp Denzel",
    author_email="phdenzel@gmail.com",
    version="0.0.dev2",
    description=("A command-line chat app for secure communication "
                 "between you and your friends!"),
    long_description=ld['data'],
    long_description_content_type=ld['content_type'],
    license='GNU General Public License v3.0',
    url="https://github.com/phdenzel/fabular",
    keywords="command line, chat, secure, encryption, server, client",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: GPLv3',
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
