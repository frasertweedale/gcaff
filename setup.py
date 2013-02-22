from setuptools import setup, find_packages

from gcaff import version

with open('README.rst') as f:
    readme = f.read()

setup(
    name='gcaff',
    version=version.VERSION,
    author='Fraser Tweedale',
    author_email='frase@frase.id.au',
    description='graphical OpenPGP signing assistant',
    long_description=readme,
    url='https://github.com/frasertweedale/gcaff',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: X11 Applications :: GTK',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2.7',
        'Topic :: Communications :: Email',
        'Topic :: Security :: Cryptography',
    ],
    packages=find_packages(),
    entry_points={'console_scripts': ['gcaff = gcaff.__main__:main']},
)
