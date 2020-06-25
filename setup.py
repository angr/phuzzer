
from distutils.core import setup

setup(
    name='phuzzer', version='8.19.4.30.pre3', description="Python wrapper for multiarch AFL",
    packages=['phuzzer', 'phuzzer.extensions', 'phuzzer.phuzzers'],
    install_requires=['tqdm','networkx']
)
