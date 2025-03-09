from setuptools import setup, find_packages
import re

VERSIONFILE="anfs/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="anfs",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,

	# Details
	url="https://github.com/skelsec/anfs",

	zip_safe = False,
	#
	# license="LICENSE.txt",
	description="Asynchronous NFSv3 protocol implementation",

	# long_description=open("README.txt").read(),
	python_requires='>=3.7',
	install_requires=[
		'unicrypto>=0.0.10',
		'asyauth>=0.0.20',
		'asysocks>=0.2.12',
		'prompt-toolkit>=3.0.2',
		'tqdm',
		'colorama',
		'asn1crypto',
		'wcwidth',
		'xdrlib3; python_version>="3.13"',
	],
	
	classifiers=[
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	entry_points={
		'console_scripts': [
			'anfsclient = anfs.examples.anfsclient:main',
		],

	}
)