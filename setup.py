"""PyAmiibo is a library for manipulating Amiibo dumps."""
import os.path
import sys

from setuptools import setup

readme_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'README.rst'))
with open(readme_path, encoding='utf-8') as f:
    readme = f.read()

setup(
    name='pyamiibo',
    version='0.2',
    description=__doc__,
    long_description=readme,
    author='Toby Fleming',
    author_email='tobywf@users.noreply.github.com',
    url='https://github.com/tobywf/pyamiibo',
    license='GPLv3',
    packages=['amiibo'],
    install_requires=['cryptography'],
    zip_safe=True,
    entry_points={
        'console_scripts': ['amiibo = amiibo.cli:main']
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development :: Libraries',
        'Operating System :: OS Independent',
    ],
    keywords='NXP NTAG NTAG213 NTAG215 NTAG216 Amiibo')
